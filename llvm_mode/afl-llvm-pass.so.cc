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

std::string instr_target;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

  };

}

// Pass the file containing the target location information as an environment variable
void initTarget(char* target_file) {
  std::ifstream stream(target_file);
  std::getline(stream, instr_target);
}

void initialize(void) {
  char* target_file = getenv("DAFL_TARGET_FILE");
  if (target_file) {
    initTarget(target_file);
  }
}

char AFLCoverage::ID = 0;
static const char *CoverageFunctionName = "puts";

Function *getCoverageFunction(Module &M) {
  LLVMContext &Ctx = M.getContext();
  Type* StringType = Type::getInt8PtrTy(Ctx);
  Type* ArgsTypes[] = {StringType};
  FunctionType *FType = FunctionType::get(Type::getInt32Ty(Ctx), ArgsTypes, false);
  Value *Coverage = dyn_cast<Value>(M.getOrInsertFunction(CoverageFunctionName, FType).getCallee());
  if (Function *F = dyn_cast<Function>(Coverage)) {
    return F;
  } else {
    errs() << "WARN: invalid function\n";
    return NULL;
  }

  return NULL;
}

bool AFLCoverage::runOnModule(Module &M) {

  initialize();
  std::stringstream ss(instr_target);
  std::string target_file, target_func, target_line;
  std::getline(ss, target_file, ':');
  std::getline(ss, target_func, ':');
  std::getline(ss, target_line);

  std::string file_name = M.getSourceFileName();
  std::size_t tokloc = file_name.find_last_of('/');
  if (tokloc != std::string::npos) {
    file_name = file_name.substr(tokloc + 1, std::string::npos);
  }
  if (file_name.compare(target_file) != 0)
    return true;

  for (auto &F : M) {
    const std::string func_name = F.getName().str();
    if (func_name.compare(target_func) == 0)
      continue;

    std::string msg = std::string("\n[FUNCTION] ") + file_name + std::string(":") + func_name;
      
    bool is_first_BB = true;
    for (auto &BB : F) {
      // Insert function coverage
      if( is_first_BB ) {
        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));
        std::vector<Value *> Args;
        Value *Str = IRB.CreateGlobalStringPtr(msg.c_str());
        Args.push_back(Str);
        Function *Fun = getCoverageFunction(M);
        CallInst *Call = IRB.CreateCall(Fun, Args, "");
        Call->setCallingConv(CallingConv::C);
        Call->setTailCall(true);
        is_first_BB = false;
      }

      for (auto &inst : BB) {
        DebugLoc dbg = inst.getDebugLoc();
        DILocation* DILoc = dbg.get();

        if (!DILoc || !DILoc->getLine()) 
          continue;  

        std::string line_str = std::to_string(DILoc->getLine());
        if (line_str.compare(target_line) != 0)
          continue;
        
        std::string line_msg = std::string("\n[LINE] ") + file_name + std::string(":") + line_str;
        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));
        std::vector<Value *> Args;
        Value *Str = IRB.CreateGlobalStringPtr(line_msg.c_str());
        Args.push_back(Str);
        Function *Fun = getCoverageFunction(M);
        CallInst *Call = IRB.CreateCall(Fun, Args, "");
        Call->setCallingConv(CallingConv::C);
        Call->setTailCall(true);
        break;
      }

    }
  }
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
