/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that propagates $gp (global pointer) values through the call graph
 * for MIPS programs, particularly kernel modules where $gp may not be set at
 * load time.
 * 
 * This analyzer identifies entry points (module_init, module_exit, exported
 * functions, functions in .init.text/.exit.text sections) and propagates
 * $gp values from them through the call graph using BFS traversal.
 * 
 * The MIPS o32 ABI treats $gp as caller-saved but "unaffected" in Ghidra's
 * calling convention, meaning it should be preserved across calls. This
 * allows $gp to flow from callers to callees.
 */
public class MipsGpPropagationAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "MIPS GP Propagation";
	private static final String DESCRIPTION =
		"Propagates $gp (global pointer) values from entry points through the call graph " +
		"for kernel modules and binaries without explicit $gp symbols.";

	// Common kernel module entry point names
	private static final Set<String> ENTRY_POINT_NAMES = Set.of(
		"init_module", "cleanup_module",
		"module_init", "module_exit",
		"_init", "_fini",
		"__init", "__exit"
	);

	// Sections that contain entry points
	private static final Set<String> ENTRY_SECTIONS = Set.of(
		".init.text", ".exit.text", ".init", ".fini"
	);

	private Register gpRegister;

	public MipsGpPropagationAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		// Run after function creation but before address analysis
		// This ensures functions exist but haven't been fully analyzed yet
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		if (!processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS"))) {
			return false;
		}
		gpRegister = program.getRegister("gp");
		return gpRegister != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Check if $gp is already set globally (from ELF loader)
		if (isGpAlreadySet(program)) {
			return true; // No need for call-graph propagation
		}

		// Find all entry point functions
		Set<Function> entryPoints = findEntryPointFunctions(program, monitor);
		if (entryPoints.isEmpty()) {
			return true;
		}

		monitor.setMessage("Propagating $gp through call graph...");
		monitor.setMaximum(entryPoints.size());
		int count = 0;

		// For each entry point, discover $gp and propagate through call graph
		for (Function entry : entryPoints) {
			monitor.checkCancelled();
			monitor.setProgress(count++);

			Long gpValue = discoverGpFromFunction(program, entry);
			if (gpValue != null) {
				propagateGpThroughCallGraph(program, entry, gpValue, monitor);
			}
		}

		return true;
	}

	/**
	 * Check if $gp is already set in program context (from ELF loader).
	 * If most executable sections have $gp set, we don't need to propagate.
	 */
	private boolean isGpAlreadySet(Program program) {
		ProgramContext context = program.getProgramContext();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isExecute()) {
				RegisterValue gpValue = context.getRegisterValue(gpRegister, block.getStart());
				if (gpValue != null && gpValue.hasValue()) {
					long gp = gpValue.getUnsignedValue().longValue();
					if (gp != 0) {
						return true; // $gp is already set
					}
				}
			}
		}
		return false;
	}

	/**
	 * Find all functions that are entry points for the module/program.
	 */
	private Set<Function> findEntryPointFunctions(Program program, TaskMonitor monitor)
			throws CancelledException {
		Set<Function> entries = new HashSet<>();
		FunctionManager funcMgr = program.getFunctionManager();
		SymbolTable symTable = program.getSymbolTable();

		// 1. External entry points
		AddressIterator entryIter = symTable.getExternalEntryPointIterator();
		while (entryIter.hasNext()) {
			monitor.checkCancelled();
			Address addr = entryIter.next();
			Function func = funcMgr.getFunctionAt(addr);
			if (func != null) {
				entries.add(func);
			}
		}

		// 2. Known entry point names
		for (String name : ENTRY_POINT_NAMES) {
			for (Symbol sym : symTable.getSymbols(name)) {
				monitor.checkCancelled();
				Function func = funcMgr.getFunctionAt(sym.getAddress());
				if (func != null) {
					entries.add(func);
				}
			}
		}

		// 3. Functions in entry sections (.init.text, .exit.text, etc.)
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			String blockName = block.getName();
			if (ENTRY_SECTIONS.contains(blockName)) {
				FunctionIterator funcIter = funcMgr.getFunctions(
					new AddressSet(block.getStart(), block.getEnd()), true);
				while (funcIter.hasNext()) {
					monitor.checkCancelled();
					entries.add(funcIter.next());
				}
			}
		}

		return entries;
	}

	/**
	 * Attempt to discover $gp value from function prologue pattern.
	 * Looks for: lui $gp, high; addiu $gp, $gp, low
	 */
	private Long discoverGpFromFunction(Program program, Function func) {
		// First check if $gp is already set in context for this function
		ProgramContext context = program.getProgramContext();
		RegisterValue gpValue = context.getRegisterValue(gpRegister, func.getEntryPoint());
		if (gpValue != null && gpValue.hasValue()) {
			long gp = gpValue.getUnsignedValue().longValue();
			if (gp != 0) {
				return gp;
			}
		}

		// Try to discover from prologue pattern
		return discoverGpFromPrologue(program, func);
	}

	/**
	 * Scan function prologue for lui/addiu pattern that sets $gp.
	 * Pattern: lui $gp, 0xHIGH; addiu $gp, $gp, 0xLOW
	 */
	private Long discoverGpFromPrologue(Program program, Function func) {
		Listing listing = program.getListing();
		Address addr = func.getEntryPoint();
		
		// Scan first 10 instructions looking for lui $gp
		Long luiValue = null;
		for (int i = 0; i < 10; i++) {
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) break;

			String mnem = instr.getMnemonicString();
			if (mnem.equals("lui") || mnem.equals("_lui")) {
				Register destReg = instr.getRegister(0);
				if (destReg != null && destReg.getName().equals("gp")) {
					// Found lui $gp, immediate
					Object[] opObjs = instr.getOpObjects(1);
					if (opObjs.length > 0 && opObjs[0] instanceof ghidra.program.model.scalar.Scalar) {
						luiValue = ((ghidra.program.model.scalar.Scalar) opObjs[0]).getUnsignedValue() << 16;
					}
				}
			}
			else if ((mnem.equals("addiu") || mnem.equals("_addiu")) && luiValue != null) {
				Register destReg = instr.getRegister(0);
				Register srcReg = instr.getRegister(1);
				if (destReg != null && destReg.getName().equals("gp") &&
					srcReg != null && srcReg.getName().equals("gp")) {
					// Found addiu $gp, $gp, immediate
					Object[] opObjs = instr.getOpObjects(2);
					if (opObjs.length > 0 && opObjs[0] instanceof ghidra.program.model.scalar.Scalar) {
						long offset = ((ghidra.program.model.scalar.Scalar) opObjs[0]).getSignedValue();
						return luiValue + offset;
					}
				}
			}

			addr = instr.getFallThrough();
			if (addr == null) break;
		}

		return null;
	}

	/**
	 * Propagate $gp value through the call graph using BFS.
	 * Since $gp is "unaffected" in the calling convention, callees
	 * inherit the caller's $gp value.
	 */
	private void propagateGpThroughCallGraph(Program program, Function startFunc,
			long gpValue, TaskMonitor monitor) throws CancelledException {
		
		ProgramContext context = program.getProgramContext();
		Set<Address> visited = new HashSet<>();
		Queue<Function> worklist = new LinkedList<>();
		
		worklist.add(startFunc);
		visited.add(startFunc.getEntryPoint());

		RegisterValue gpRegValue = new RegisterValue(gpRegister, BigInteger.valueOf(gpValue));

		while (!worklist.isEmpty()) {
			monitor.checkCancelled();
			Function func = worklist.poll();
			Address entry = func.getEntryPoint();

			// Set $gp for this function if not already set
			RegisterValue existing = context.getRegisterValue(gpRegister, entry);
			if (existing == null || !existing.hasValue() || 
				existing.getUnsignedValue().longValue() == 0) {
				try {
					// Set $gp at function entry point
					context.setRegisterValue(entry, entry, gpRegValue);
				}
				catch (ContextChangeException e) {
					Msg.debug(this, "Could not set $gp at " + entry + ": " + e.getMessage());
				}
			}

			// Add called functions to worklist
			Set<Function> calledFuncs = func.getCalledFunctions(monitor);
			for (Function callee : calledFuncs) {
				if (!visited.contains(callee.getEntryPoint())) {
					visited.add(callee.getEntryPoint());
					worklist.add(callee);
				}
			}
		}

		Msg.info(this, "Propagated $gp=0x" + Long.toHexString(gpValue) + 
			" from " + startFunc.getName() + " to " + visited.size() + " functions");
	}
}

