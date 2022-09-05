/*
 *
 *   The core ReZZan instrumentation module.
 *   It wraps all stack, global variables with NONCE value.
 *      inserts boundary checking functions to all LOAD/SET instructions.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fstream>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/IR/InlineAsm.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"

#include "llvm/Transforms/Utils/ModuleUtils.h"

#ifdef NDEBUG
#undef NDEBUG
#endif


/*
 * LLVM ReZZan pass.
 */
namespace
{
    class ReZZan : public ModulePass
    {
        public:

            static char ID;
            static size_t nonce_size;
            ReZZan();

            bool runOnModule(Module &M) override;
    };
}

char ReZZan::ID = 0;
size_t ReZZan::nonce_size = 61;

ReZZan::ReZZan() : ModulePass(ID) {
}

/*
 * Build the check function.
 */
static void buildCheck(Module *M)
{
    Function *F = M->getFunction("__rezzan_check");
    if (F != nullptr)
        F->setDoesNotThrow();

    std::string Asm;
    /*
     * rdi: the origin pointer of the last byte [retain the delta]
     * rax: the first token [check the token]
     * rcx: the fs:40 value [the token baseline]
     * rdx: the second token [check the page size offset]
     * r8: the second token [check the token]
     * r9: the second token [check the delta]
     */
    Asm +=
        ".type __rezzan_check, @function\n"
        ".weak __rezzan_check\n"
        "__rezzan_check:\n"
        "addq $-0x1, %rdi\n"
        "addq %rsi, %rdi\n"
        "mov %rdi, %rax\n"
        "andq $-0x8, %rax\n"
        "mov %rax, %rdx\n"
        "mov (%rax), %rax\n";
    if (ReZZan::nonce_size == 61) {
        Asm +=
            "andq $-0x8, %rax\n";
    }
    Asm +=
        "mov 0x10000, %rcx\n"
        "addq %rcx, %rax\n"
        "jne .Lok_a\n"
        "ud2\n"
        ".Lok_a:\n";
    if (ReZZan::nonce_size == 61) {
        Asm +=
            "addq $0x8, %rdx\n"
            "mov %rdx, %r8\n"
            "and $0xfff, %edx\n"
            "test %edx, %edx\n"
            "je .Lok2_a\n"
            "mov (%r8), %r8\n"
            "mov %r8, %r9\n"
            "andq $-0x8, %r8\n"
            "addq %rcx, %r8\n"
            "jne .Lok2_a\n"
            "andq $0x7, %r9\n"
            "andq $0x7, %rdi\n"
            "test %r9, %r9\n"
            "je .Lok2_a\n"
            "cmp %rdi, %r9\n"
            "ja .Lok2_a\n"
            "ud2\n"
            ".Lok2_a:\n";
    }
    Asm +=
        "retq\n";
    M->appendModuleInlineAsm(Asm);
}

/*
 * Build the initialization code.
 */
static void buildInit(Module *M, std::vector<Constant *> &Metadata_gbl_overflow, 
                            std::vector<Constant *> &Metadata_gbl_underflow)
{
    {
        // Stack initialization
        Function *F = M->getFunction("__init_stk_obj");
        if (F != nullptr)
            F->setDoesNotThrow();

        std::string Asm;                // Wrap the stack variables with underflow and overflow token
        Asm +=
            ".type __init_stk_obj, @function\n"
            ".weak __init_stk_obj\n"
            "__init_stk_obj:\n"
            "\tmov 0x10000, %rax\n"
            "\tnegq %rax\n"
            "\tmov %rax,(%rdi)\n"
            "\tadd $8,%rdi\n"
            "\tmov %rax,(%rdi)\n"
            "\tadd $8,%rdi\n";
        if (ReZZan::nonce_size == 61) {
            Asm +=
                "\tandq $-8,%rax\n";
        }
        Asm +=
            "\tlea (%rdi,%rsi),%rsi\n"  // rdi: the start of the allocated memory, rsi: the start of the overflow detection
            "\tmov %rsi,%rdx\n"
            "\tadd $7, %rsi\n"
            "\tandq $-8,%rsi\n"
            ".Lloop:\n"
            "\tcmpq %rsi,%rdi\n"
            "\tjge .Lexit\n"
            "\tmovabsq $0xbebebebebebebebe, %rcx\n"
            "\tmovq %rcx, (%rdi)\n"
            "\tadd $8,%rdi\n"
            "\tjmp .Lloop\n"
            ".Lexit:\n";
        if (ReZZan::nonce_size == 61) {
            Asm +=
                "\tandq $0x7,%rdx\n"
                "\txor %rdx,%rax\n";
        }
        Asm +=
            "\tmov %rax,(%rsi)\n"
            "\tretq\n";

        M->appendModuleInlineAsm(Asm);
    }

    {
        // Global initialization
        if (Metadata_gbl_overflow.size() == 0 || Metadata_gbl_underflow.size() == 0)
            return;

        // The global ctor function
        LLVMContext &Cxt = M->getContext();
        llvm::FunctionType *glbFunTy = llvm::FunctionType::get(
        Type::getVoidTy(Cxt), {}, false);
        Function *F = Function::Create(glbFunTy, GlobalValue::InternalLinkage, "__init_gbl_objs_ctor", M);
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);
        IRBuilder<> builder(Entry);

        // The overflow instrumentation of global variables
        Type *OverflowElemTy = Metadata_gbl_overflow[0]->getType();
        Metadata_gbl_overflow.push_back(ConstantPointerNull::get(builder.getInt8PtrTy()));
        ArrayType *OverflowArrayTy = ArrayType::get(OverflowElemTy, Metadata_gbl_overflow.size());
        Constant *OverflowArrayInit = ConstantArray::get(OverflowArrayTy, Metadata_gbl_overflow);
        GlobalVariable *OverflowGV = new GlobalVariable(*M, OverflowArrayTy, false, // set a new global variable array storing all canaries
            GlobalValue::InternalLinkage, OverflowArrayInit, "");

        FunctionCallee OverflowInit = M->getOrInsertFunction("__init_gbl_overflow", // call the assembly code to initialize the array
            builder.getVoidTy(), builder.getInt8PtrTy()->getPointerTo());

        Value *OverflowGVArray = builder.CreateBitCast(OverflowGV,
            builder.getInt8PtrTy()->getPointerTo());
        builder.CreateCall(OverflowInit, {OverflowGVArray});

        // The underflow instrumentation of global variables
        Type *UnderflowElemTy = Metadata_gbl_underflow[0]->getType();
        Metadata_gbl_underflow.push_back(ConstantPointerNull::get(builder.getInt8PtrTy()));
        ArrayType *UnderflowArrayTy = ArrayType::get(UnderflowElemTy, Metadata_gbl_underflow.size());
        Constant *UnderflowArrayInit = ConstantArray::get(UnderflowArrayTy, Metadata_gbl_underflow);
        GlobalVariable *UnderflowGV = new GlobalVariable(*M, UnderflowArrayTy, false, // set a new global variable array storing all canaries
            GlobalValue::InternalLinkage, UnderflowArrayInit, "");

        FunctionCallee UnderflowInit = M->getOrInsertFunction("__init_gbl_underflow", // call the assembly code to initialize the array
            builder.getVoidTy(), builder.getInt8PtrTy()->getPointerTo());

        Value *UnderflowGVArray = builder.CreateBitCast(UnderflowGV,
            builder.getInt8PtrTy()->getPointerTo());
        builder.CreateCall(UnderflowInit, {UnderflowGVArray});
        builder.CreateRetVoid();

        appendToGlobalCtors(*M, F, 1);

        std::string Asm; // Polulate all elements in the array with fixed values
        // Overflow assembly code
        Asm +=
            ".type __init_gbl_overflow, @function\n"
            ".weak __init_gbl_overflow\n"
            "__init_gbl_overflow:\n"
            "\tmovq (%rdi),%rsi\n"
            "\taddq $8,%rdi\n"
            "\ttestq %rsi,%rsi\n"
            "\tje .Lreturnof\n";
        if (ReZZan::nonce_size == 61) {
            Asm +=
                "\tmov %rsi, %rdx\n"
                "\tandq $7, %rdx\n";
        }
        Asm +=
            "\tadd $7,%rsi\n"
            "\tandq $-8,%rsi\n"
            "\tlea __start___rezzan_gbls(%rip), %rax\n"
            "\tcmpq %rax,%rsi\n"
            "\tjl __init_gbl_overflow\n"
            "\tlea __stop___rezzan_gbls(%rip),%rax\n"
            "\tcmpq %rax,%rsi\n"
            "\tjge __init_gbl_overflow\n"
            "\tmov 0x10000,%rax\n"
            "\tnegq %rax\n";
        if (ReZZan::nonce_size == 61) {
            Asm +=
                "\txorq %rdx, %rax\n";
        }
        Asm +=
            "\tmov %rax,(%rsi)\n"
            "\tjmp __init_gbl_overflow\n"
            ".Lreturnof:\n"
            "\tretq\n";

        // Underflow assembly code
        Asm +=
            ".type __init_gbl_underflow, @function\n"
            ".weak __init_gbl_underflow\n"
            "__init_gbl_underflow:\n"
            "\tmovq (%rdi),%rsi\n"
            "\taddq $8,%rdi\n"
            "\ttestq %rsi,%rsi\n"
            "\tje .Lreturnuf\n"
            "\tlea __start___rezzan_gbls(%rip), %rax\n"
            "\tcmpq %rax,%rsi\n"
            "\tjl __init_gbl_underflow\n"
            "\tlea __stop___rezzan_gbls(%rip),%rax\n"
            "\tcmpq %rax,%rsi\n"
            "\tjge __init_gbl_underflow\n"

            "\tmov 0x10000,%rax\n"
            "\tnegq %rax\n"
            "\tandq $-8,%rax\n"
            "\tmov %rax,(%rsi)\n"
            "\taddq $8,%rsi\n"
            "\tmov %rax,(%rsi)\n"
            "\tjmp __init_gbl_underflow\n"
            ".Lreturnuf:\n"
            "\tretq\n";
        M->appendModuleInlineAsm(Asm);
    }

}

/*
 * Replace allocas (stack allocation).
 */
static void replaceAlloca(Module *M, Instruction *I,
    std::vector<Instruction *> &dels)
{
    auto *Alloca = dyn_cast<llvm::AllocaInst>(I);
    if (Alloca == nullptr)
        return;

    Value *Size = Alloca->getArraySize(); // get the number of element allocated
    Type *Ty = Alloca->getAllocatedType(); // get the type of element allocated
    assert(Ty->isSized());

    IRBuilder<> builder(I);

    const DataLayout &DL = M->getDataLayout(); // get the original data layout
    Value *OldSize = builder.CreateMul(Size,  // old size = the number of new element * the size of each element
        builder.getInt64(DL.getTypeAllocSize(Ty)));
    Value *tmpSize = builder.CreateAdd(OldSize, builder.getInt64(15)); // Calculate the delta size of overflow token

    Value *NewSize = builder.CreateAdd(tmpSize, // new size = old size + 16 (underflow) + delta (overflow)
        builder.getInt64(2 * sizeof(uint64_t)));

    AllocaInst *NewAlloca = builder.CreateAlloca(builder.getInt8Ty(), // rewrite the new allocation instruction
        NewSize);
    NewAlloca->setAlignment(Align(2 * sizeof(uint64_t)));

    FunctionCallee Init = M->getOrInsertFunction("__init_stk_obj",
        builder.getVoidTy(), builder.getInt8PtrTy(), builder.getInt64Ty());

    builder.CreateCall(Init, {NewAlloca, OldSize}); // call the token initialization fun with allocation pointer and size
    Value *Ptr0 = builder.CreateGEP(NewAlloca, builder.getInt64(2 * sizeof(uint64_t)));
    Value *Ptr = builder.CreateBitCast(Ptr0, Alloca->getType()); // convert the pointer to the original pointer
    std::vector<User *> Replace, Lifetimes; // Update the user info
    for (User *Usr: Alloca->users())
    {
        if (auto Intr = dyn_cast<IntrinsicInst>(Usr))
        {
            if (Intr->getIntrinsicID() == Intrinsic::lifetime_start ||
                Intr->getIntrinsicID() == Intrinsic::lifetime_end)
            {
                Lifetimes.push_back(Intr);
                continue;
            }
        }
        if (BitCastInst *Cast = dyn_cast<BitCastInst>(Usr))
        {
            for (User *Usr2: Cast->users())
            {
                IntrinsicInst *Intr = dyn_cast<IntrinsicInst>(Usr2);
                if (Intr == nullptr)
                    continue;
                if (Intr->getIntrinsicID() == Intrinsic::lifetime_start ||
                        Intr->getIntrinsicID() == Intrinsic::lifetime_end)
                    Lifetimes.push_back(Usr2);
            }
        }
        Replace.push_back(Usr);
    }
    for (User *Usr: Replace)
        Usr->replaceUsesOfWith(Alloca, Ptr);
    for (User *Usr: Lifetimes)
    {
        if (auto *Lifetime = dyn_cast<Instruction>(Usr))
            dels.push_back(Lifetime);
    }

    Alloca->replaceAllUsesWith(Ptr);
    dels.push_back(Alloca);
}

/*
 * Replace global variables
 */
static void replaceGlobal(Module *M, GlobalVariable *GV,
    std::vector<Constant *> &Metadata_gbl_overflow, std::vector<Constant *> &Metadata_gbl_underflow,
    std::vector<GlobalVariable *> &dels)
{
    if (GV->isDeclaration() || GV->hasSection() || GV->isThreadLocal())
        return;
    switch (GV->getLinkage())
    {
        case GlobalValue::ExternalLinkage:
        case GlobalValue::InternalLinkage:
        case GlobalValue::PrivateLinkage:
        case GlobalValue::WeakAnyLinkage:
        case GlobalValue::WeakODRLinkage:
        case GlobalValue::CommonLinkage:
            break;
        default:
            return;     // Weird linkage
    }

    Type *Ty = GV->getType();
    PointerType *PtrTy = dyn_cast<PointerType>(Ty);
    if (PtrTy == nullptr)
        return;
    Ty = PtrTy->getElementType();
    if (!Ty->isSized())
        return;

    const DataLayout &DL = M->getDataLayout();
    size_t old_size = DL.getTypeAllocSize(Ty);                                  // acquire the size of the original data
    size_t delta_size = old_size % sizeof(uint64_t) > 0 ? sizeof(uint64_t) - old_size % sizeof(uint64_t) : 0;
    size_t underflow_token_size = sizeof(uint64_t) * 2;
    size_t overflow_token_size = sizeof(uint64_t) + delta_size;

    LLVMContext &Cxt = M->getContext();
    Type *UnderflowTokenTy = ArrayType::get(Type::getInt8Ty(Cxt), underflow_token_size);
    Type *OverflowTokenTy = ArrayType::get(Type::getInt8Ty(Cxt), overflow_token_size);
    StructType *WrapTy = StructType::get(Cxt, {UnderflowTokenTy, Ty, OverflowTokenTy}, false);      // create the data structure of the token

    Constant *WrapInit = ConstantStruct::get(WrapTy, {Constant::getNullValue(UnderflowTokenTy),       // construct the initialization function of the new data strucutre
        GV->getInitializer(), Constant::getNullValue(OverflowTokenTy)});

    GlobalVariable *NewGV = new GlobalVariable(*M, WrapTy, GV->isConstant(),// create a global variable from the new data structure
        GV->getLinkage(), WrapInit, "", GV, GV->getThreadLocalMode());
    NewGV->copyAttributesFrom(GV);                                          // copy all previous attributes to the new one
    NewGV->setConstant(false);
    NewGV->setSection("__rezzan_gbls");                                     // put all new global variables in the new section
    NewGV->setAlignment(Align(2 * sizeof(uint64_t)));
    Type *Int32Ty = Type::getInt32Ty(Cxt);
    Constant *Idxs01[2] = {ConstantInt::get(Int32Ty, 0),
                           ConstantInt::get(Int32Ty, 1)};
    GV->replaceAllUsesWith(
        ConstantExpr::getGetElementPtr(WrapTy, NewGV, Idxs01, true));       // Update all pointers which use the global variable

    NewGV->setName(std::string("rezzan_gv_")+GV->getName());
    dels.push_back(GV);

    Constant *Idxs00[2] = {ConstantInt::get(Int32Ty, 0),
                           ConstantInt::get(Int32Ty, 0)};
    Constant *UnderflowTokenPtr = ConstantExpr::getGetElementPtr(WrapTy, NewGV,
        Idxs00, true);
    Metadata_gbl_underflow.push_back(ConstantExpr::getBitCast(UnderflowTokenPtr, Type::getInt8PtrTy(Cxt)));  // put the pointer pointing to the underflow token to the metadata

    Constant *Idxs02[2] = {ConstantInt::get(Int32Ty, 0),
                           ConstantInt::get(Int32Ty, 2)};
    Constant *OverflowTokenPtrWithDelta = ConstantExpr::getGetElementPtr(WrapTy, NewGV,
        Idxs02, true);
    Metadata_gbl_overflow.push_back(ConstantExpr::getBitCast(OverflowTokenPtrWithDelta, Type::getInt8PtrTy(Cxt)));   // put the pointer pointing to the overflow token to the metadata

    switch (GV->getLinkage())
    {
    case llvm::GlobalValue::ExternalLinkage:
    case llvm::GlobalValue::WeakAnyLinkage:
    case llvm::GlobalValue::WeakODRLinkage:
    case llvm::GlobalValue::CommonLinkage:
    {
        // We need to alias GV with NewGV offset by underflow token.
        // Unfortunately LLVM can not correctly alias all GV in cross-file references,
        // so we use inline asm instead:
        std::string Asm(".globl ");
        Asm += GV->getName();
        Asm += '\n';
        Asm += ".set ";
        Asm += GV->getName();
        Asm += ", ";
        Asm += NewGV->getName();
        Asm += '+';
        Asm += std::to_string(underflow_token_size);
        M->appendModuleInlineAsm(Asm);
        break;
    }
    default:
        break;
    }

}

/*
 * Determine if a memory access should be checked.
 * If the laod or store instruction operate less than unit memory, we do not need to check it
 */
static bool shouldCheck(Module *M, Value *Ptr)
{
    const DataLayout *DL = &M->getDataLayout();
    ObjectSizeOffsetVisitor Visitor(*DL, /*TLI=*/nullptr, Ptr->getContext());
    SizeOffsetType Offset = Visitor.compute(Ptr);
    if (!Visitor.bothKnown(Offset))
        return true;
    size_t size      = (size_t)Offset.first.getZExtValue();
    off_t  offset    = (off_t)Offset.second.getSExtValue();
    Type *Ty = Ptr->getType();
    size_t type_size = UINT32_MAX;
    if (auto *PtrTy = dyn_cast<PointerType>(Ty))
    {
        Ty = PtrTy->getElementType();
        type_size = DL->getTypeAllocSize(Ty);
    }
    return (offset < 0 || (size_t)offset >= size + type_size);
}

/*
 * Insert a memory access check if necessary.
 */
static bool insertCheck(Module *M, Instruction *I)
{
    const DataLayout *DL = &M->getDataLayout();
    IRBuilder<> builder(I);

    Value *Ptr = nullptr;
    if (LoadInst *Load = dyn_cast<LoadInst>(I))
        Ptr = Load->getPointerOperand();
    else if (StoreInst *Store = dyn_cast<StoreInst>(I))
        Ptr = Store->getPointerOperand();
    if (Ptr == nullptr)
        return false;
    if (!shouldCheck(M, Ptr))
        return false;
    size_t size = 0;
    Type *Ty = Ptr->getType();
    if (auto *PtrTy = dyn_cast<PointerType>(Ty))
    {
        Ty = PtrTy->getElementType();
        size = DL->getTypeAllocSize(Ty);
    }
    Value *Size = builder.getInt64(size); // calculating the affected memory size

    Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy()); // cast the real operating pointer address

    FunctionCallee Check = M->getOrInsertFunction("__rezzan_check",
        builder.getVoidTy(), builder.getInt8PtrTy(),
        builder.getInt64Ty());

    builder.CreateCall(Check, {Ptr, Size});
    return true;
}

/*
 * Disable the loop idom optimization in LLVM.
 * Because these optimizations will jump over our instrumentation.
 */
static void replaceMemInst(Module *M, Instruction *I,
    std::vector<Instruction *> &dels)
{
    if (MemCpyInst* MemInst = dyn_cast<MemCpyInst>(I)) {
        IRBuilder<> builder(I);
        FunctionCallee OriginMemInst = M->getOrInsertFunction("memcpy",
        builder.getVoidTy(), builder.getInt8PtrTy(),
        builder.getInt8PtrTy(), builder.getInt64Ty());
        Value* Dest = MemInst->getDest();
	    Value* Src = MemInst->getSource();
	    Value* Size = MemInst->getLength();
        Dest = builder.CreateBitCast(Dest, builder.getInt8PtrTy());
        Src = builder.CreateBitCast(Src, builder.getInt8PtrTy());
        builder.CreateCall(OriginMemInst, {Dest, Src, Size});
        dels.push_back(MemInst);
    }
}

/*
 * Read a configuration value.
 */
static size_t get_config(const char *name, size_t _default)
{
    const char *str = getenv(name);
    if (str == NULL)
        return _default;
    char *end = NULL;
    errno = 0;
    size_t val = (size_t)strtoull(str, &end, 0);
    if (errno != 0)
        errs()<<"failed to parse string \""<<str<<"\" into an integer: "<<strerror(errno);
    else if (end == NULL || *end != '\0')
        errs()<<"failed to parse string \""<<str<<"\" into an integer";
    return val;
}


/*
 * Entry.
 */
bool ReZZan::runOnModule(Module &M)
{
    uint16_t alloca_num = 0;
    uint16_t global_num = 0;
    uint16_t heap_num = 0;

    nonce_size = get_config("REZZAN_NONCE_SIZE", 61);

    {
        std::vector<Instruction *> dels;
        for (auto &F : M)
            for (auto &BB: F)
                for (auto &I: BB)
                    replaceAlloca(&M, &I, dels);
        alloca_num += dels.size();
        for (auto *I: dels)
            I->eraseFromParent();
    }

    std::vector<Constant *> Metadata_gbl_overflow;
    std::vector<Constant *> Metadata_gbl_underflow;
    {
        std::vector<GlobalVariable *> dels;
        for (auto &GV: M.getGlobalList())
            replaceGlobal(&M, &GV, Metadata_gbl_overflow, Metadata_gbl_underflow, dels);
        global_num += dels.size();
        for (auto *V: dels)
            V->eraseFromParent();
    }

    for (auto &F : M)
        for (auto &BB: F)
            for (auto &I: BB)
                heap_num += insertCheck(&M, &I) ? 1 : 0;

    {
        std::vector<Instruction *> dels;
        for (auto &F : M)
            for (auto &BB: F)
                for (auto &I: BB)
                    replaceMemInst(&M, &I, dels);
        for (auto *I: dels)
            I->eraseFromParent();
    }

    buildCheck(&M);
    buildInit(&M, Metadata_gbl_overflow, Metadata_gbl_underflow);

    //errs() << alloca_num << " " << global_num << " " << heap_num << "\n";

    if (getenv("REZZAN_DEBUG") != nullptr)
    {
        std::string outName(M.getName());
        outName += ".rezzan.out.ll";
        errs() << "writing output: " << outName.c_str() << "\n";
        std::error_code EC;
        llvm::raw_fd_ostream out(outName.c_str(), EC, llvm::sys::fs::F_None);
        M.print(out, nullptr);
    }

    return true;
}

/*
 * LLVM boilerplate.
 */
static void registerReZZanPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM)
{
  	PM.add(new ReZZan());
}

static RegisterStandardPasses RegisterReZZanPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerReZZanPass);

static RegisterStandardPasses RegisterReZZanPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerReZZanPass);

static RegisterPass<ReZZan> X("rezzan", "ReZZan pass");
