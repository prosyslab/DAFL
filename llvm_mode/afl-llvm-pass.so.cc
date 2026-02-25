/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <set>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm/Support/CommandLine.h"

using namespace llvm;

bool selective_coverage = false;
bool dfg_scoring = false;
bool no_filename_match = false;
std::set<std::string> instr_targets;
std::map<std::string,std::pair<unsigned int,unsigned int>> dfg_node_map;


namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}


void initCoverageTarget(char* select_file) {
  std::string line;
  std::ifstream stream(select_file);

  while (std::getline(stream, line))
    instr_targets.insert(line);
}


void initDFGNodeMap(char* dfg_file) {
  unsigned int idx = 0;
  std::string line;
  std::ifstream stream(dfg_file);

  while (std::getline(stream, line)) {
    std::size_t space_idx = line.find(" ");
    std::string score_str = line.substr(0, space_idx);
    std::string targ_line = line.substr(space_idx + 1, std::string::npos);
    int score = stoi(score_str);
    dfg_node_map[targ_line] = std::make_pair(idx++, (unsigned int) score);
    if (idx >= DFG_MAP_SIZE) {
      std::cout << "Input DFG is too large (check DFG_MAP_SIZE)" << std::endl;
      exit(1);
    }
  }
}


void initialize(void) {
  char* select_file = getenv("DAFL_SELECTIVE_COV");
  char* dfg_file = getenv("DAFL_DFG_SCORE");

  if (select_file) {
    selective_coverage = true;
    initCoverageTarget(select_file);
  }

  if (dfg_file) {
    dfg_scoring = true;
    initDFGNodeMap(dfg_file);
  }

  if (getenv("DAFL_NO_FILENAME_MATCH")) no_filename_match = true;
}


char AFLCoverage::ID = 0;


bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  initialize();

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLMapDFGPtr =
      new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_dfg_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */

  int inst_blocks = 0;
  int skip_blocks = 0;
  int inst_dfg_nodes = 0;
  std::string file_name = M.getSourceFileName();
  std::set<std::string> covered_targets;

  

  for (auto &F : M) {

    // Get file name from function in case the module is a combined bc file.
    if (auto *SP = F.getSubprogram()) {
        file_name = SP->getFilename().str();
    }

    // Keep only the file name.
    std::size_t tokloc = file_name.find_last_of('/');
    if (tokloc != std::string::npos) {
      file_name = file_name.substr(tokloc + 1, std::string::npos);
    }

    bool is_inst_targ = false;
    const std::string func_name = F.getName().str();
    std::set<std::string>::iterator it;

    /* Check if this function is our instrumentation target. */
    if (selective_coverage) {
      for (it = instr_targets.begin(); it != instr_targets.end(); ++it) {
        std::size_t colon = (*it).find(":");
        std::string target_file = (*it).substr(0, colon);
        std::string target_func = (*it).substr(colon + 1, std::string::npos);

        if (no_filename_match || file_name.compare(target_file) == 0) {
          if (func_name.compare(target_func) == 0) {
            is_inst_targ = true;
            covered_targets.insert(*it);
            break;
          }
        }
      }
    } else is_inst_targ = true; // If disabled, instrument all the blocks.

    /* Now iterate through the basic blocks of the function. */

    for (auto &BB : F) {
      bool is_dfg_node = false;
      unsigned int node_idx = 0;
      unsigned int node_score = 0;

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (is_inst_targ) {
        inst_blocks++;
      }
      else {
        skip_blocks++;
        /* Set prev_loc to 0 to indicate that this block is uninstrumented. */
        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, 0), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        continue;
      }

      /* Iterate through the instructions in the basic block to check if this
       * block is a DFG node. If so, retrieve its proximity score. */

      if (dfg_scoring) {
        for (auto &inst : BB) {
          DebugLoc dbg = inst.getDebugLoc();
          DILocation* DILoc = dbg.get();
          if (DILoc && DILoc->getLine()) {
            int line_no = DILoc->getLine();
            std::ostringstream stream;
            stream << file_name << ":" << line_no;
            std::string targ_str = stream.str();
            if (dfg_node_map.count(targ_str) > 0) {
              is_dfg_node = true;
              auto node_info = dfg_node_map[targ_str];
              node_idx = node_info.first;
              node_score = node_info.second;
              inst_dfg_nodes++;
              break;
            }
          }
        }
      } // If disabled, we don't have to do anything here.

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      if (is_dfg_node) {
        /* Update DFG coverage map. */
        LoadInst *DFGMap = IRB.CreateLoad(AFLMapDFGPtr);
        DFGMap->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        ConstantInt * Idx = ConstantInt::get(Int32Ty, node_idx);
        ConstantInt * Score = ConstantInt::get(Int32Ty, node_score);
        Value *DFGMapPtrIdx = IRB.CreateGEP(DFGMap, Idx);
        IRB.CreateStore(Score, DFGMapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      }
    }
  }

  /* Say something nice. */
  for (auto it = covered_targets.begin(); it != covered_targets.end(); ++it)
    std::cout << "Covered " << (*it) << std::endl;
  OKF("Selected blocks: %u, skipped blocks: %u. instrumented DFG nodes: %u",
      inst_blocks, skip_blocks, inst_dfg_nodes);

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
