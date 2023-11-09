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

char AFLCoverage::ID = 0;
static const char *CoverageFunctionName = "fputs";
static const char *CoverageFile = "stderr";


Function *getCoverageFunction(Module &M) {
  LLVMContext &Ctx = M.getContext();
  Type* StringType = Type::getInt8PtrTy(Ctx);
  Type *FilePtrType = Type::getInt8PtrTy(Ctx);
  Type *ArgsTypes[] = {StringType, FilePtrType};
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
  LLVMContext &Ctx = M.getContext();

  std::string file_name = M.getSourceFileName();
  std::size_t tokloc = file_name.find_last_of('/');
  bool is_first_BB, is_first_inst;
  if (tokloc != std::string::npos) {
    file_name = file_name.substr(tokloc + 1, std::string::npos);
  }

  for (auto &F : M) {
    const std::string func_name = F.getName().str();
    std::string msg = std::string("[FUNCTION] ") + file_name + std::string(":") + func_name;
    is_first_BB = true;

    for (auto &BB : F) {
      // Insert function coverage
      if( is_first_BB ) {
        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));
        std::vector<Value *> Args;
        Value *Str = IRB.CreateGlobalStringPtr(msg.c_str());
        Value *File = IRB.CreateGlobalStringPtr("/dev/stderr");
        Value *Fptr = IRB.CreateBitOrPointerCast(File, Type::getInt8PtrTy(Ctx));
        Args.push_back(Str);
        Args.push_back(Fptr);
        Function *Fun = getCoverageFunction(M);
        CallInst *Call = IRB.CreateCall(Fun, Args, "");
        Call->setCallingConv(CallingConv::C);
        Call->setTailCall(false);
        is_first_BB = false;
      }

      is_first_inst = true;
      for (auto &inst : BB) {
        // Insert line coverage
        if (is_first_inst)
          is_first_inst = false;
        else
          break;
        
        DebugLoc dbg = inst.getDebugLoc();
        DILocation* DILoc = dbg.get();
        if (DILoc && DILoc->getLine()) {
          std::string line_str = std::to_string(DILoc->getLine());
          std::string line_msg = std::string("[LINE] ") + file_name + std::string(":") + line_str;

          IRBuilder<> IRB(&(inst));
          std::vector<Value *> Args;
          Value *Str = IRB.CreateGlobalStringPtr(line_msg.c_str());
          Value *File = IRB.CreateGlobalStringPtr("/dev/stderr");
          Value *Fptr = IRB.CreateBitOrPointerCast(File, Type::getInt8PtrTy(Ctx));
          Args.push_back(Str);
          Args.push_back(Fptr);
          Function *Fun = getCoverageFunction(M);
          CallInst *Call = IRB.CreateCall(Fun, Args, "");
          Call->setCallingConv(CallingConv::C);
          Call->setTailCall(false);
        }
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
