package avranalysis.core;

import java.util.Arrays;

import javr.core.AvrDecoder;
import javr.core.AvrInstruction;
import javr.core.AvrInstruction.AbsoluteAddress;
import javr.core.AvrInstruction.FlagRelativeAddress;
import javr.core.AvrInstruction.RelativeAddress;
import javr.io.HexFile;
import javr.memory.ElasticByteMemory;

public class StackAnalysis {
	/**
	 * Contains the raw bytes of the given firmware image being analysed.
	 */
	private ElasticByteMemory firmware;

	/**
	 * The decoder is used for actually decoding an instruction.
	 */
	private AvrDecoder decoder = new AvrDecoder();

	/**
	 * Records the maximum height seen so far.
	 */
	private int maxHeight;

	/**
	 *
	 * @param firmware
	 */
	public StackAnalysis(HexFile hf) {
		// Create firmware memory
		this.firmware = new ElasticByteMemory();
		// Upload image to firmware memory
		hf.uploadTo(firmware);
	}

	/**
	 * Apply the stack analysis to the given firmware image producing a maximum
	 * stack usage (in bytes).
	 *
	 * @return
	 */
	public int apply() {
		// Reset the maximum, height
		this.maxHeight = 0;
		// Traverse instructions starting at beginning
		traverse(0, 0);
		// Return the maximum height observed
		return maxHeight;
	}

	/**
	 * Traverse the instruction at a given pc address, assuming the stack has a
	 * given height on entry.
	 *
	 * @param pc
	 *            Program Counter of instruction to traverse
	 * @param currentHeight
	 *            Current height of the stack at this point (in bytes)
	 * @return
	 */
	private void traverse(int pc, int currentHeight) {
		// Check whether current stack height is maximum
		maxHeight = Math.max(maxHeight, currentHeight);
		// Check whether we have terminated or not
		if ((pc * 2) >= firmware.size()) {
			// We've gone over end of instruction sequence, so stop.
			return;
		}
		// Process instruction at this address
		AvrInstruction instruction = decodeInstructionAt(pc);
		// Move to the next logical instruction as this is always the starting point.
		int next = pc + instruction.getWidth();
		//
		process(instruction, next, currentHeight);
	}

	/**
	 * Process the effect of a given instruction.
	 *
	 * @param instruction
	 *            Instruction to process
	 * @param pc
	 *            Program counter of following instruction
	 * @param currentHeight
	 *            Current height of the stack at this point (in bytes)
	 */
	private void process(AvrInstruction instruction, int pc, int currentHeight) {
		switch (instruction.getOpcode()) {
		case BREQ:
		case BRGE:
		case BRLT: {
			RelativeAddress branch = (RelativeAddress) instruction;
			//
			throw new RuntimeException("implement me!");
		}
		case SBRS: {
			throw new RuntimeException("implement me!");
		}
		case CALL: {
			AbsoluteAddress branch = (AbsoluteAddress) instruction;
			//
			throw new RuntimeException("implement me!");
		}
		case RCALL: {
			RelativeAddress branch = (RelativeAddress) instruction;
			//
			throw new RuntimeException("implement me!");
		}
		case JMP: {
			AbsoluteAddress branch = (AbsoluteAddress) instruction;
			//
			throw new RuntimeException("implement me!");
		}
		case RJMP: {
			// NOTE: this one is implemented for you.
			RelativeAddress branch = (RelativeAddress) instruction;
			// Check whether infinite loop; if so, terminate.
			if (branch.k != -1) {
				// Explore the branch target
				traverse(pc + branch.k, currentHeight);
			}
			//
			break;
		}
		case RET:
		case RETI:
			throw new RuntimeException("implement me!");
		case PUSH:
		  traverse(pc, currentHeight+1);
		  break;
		case POP:
		  traverse(pc, currentHeight-1);
      break;
		default:
			// Indicates a standard instruction where control is transferred to the
			// following instruction.
			traverse(pc, currentHeight);
		}
	}

	/**
	 * Decode the instruction at a given PC location.
	 *
	 * @param pc
	 * @return
	 */
	private AvrInstruction decodeInstructionAt(int pc) {
		return decoder.decode(firmware, pc);
	}
}