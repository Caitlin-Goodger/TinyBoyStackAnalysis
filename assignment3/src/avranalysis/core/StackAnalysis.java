package avranalysis.core;

import java.util.ArrayList;
import javr.core.AvrDecoder;
import javr.core.AvrInstruction;
import javr.core.AvrInstruction.AbsoluteAddress;
import javr.core.AvrInstruction.RelativeAddress;
import javr.io.HexFile;
import javr.memory.ElasticByteMemory;

/**
 * Stack Analysis class.
 * 
 * @author Caitlin
 *
 */
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
   * Records a list of all the previous instructions.
   */
  private ArrayList<AvrInstruction> previousIn = new ArrayList<AvrInstruction>();
  
  /**
   * Records a list of all the previous stack heights.
   */
  private ArrayList<Integer> previousStackHeight = new ArrayList<Integer>();
  
  /** 
   * Records a list of all the previous program counter values. 
   */
  private ArrayList<Integer> previousPC = new ArrayList<Integer>();
  
  

  /**
   * Constructor for Stack Analysis class.
   * 
   * @param hf = hexFile to read
   */
  public StackAnalysis(HexFile hf) {
    // Create firmware memory
    this.firmware = new ElasticByteMemory();
    // Upload image to firmware memory
    hf.uploadTo(this.firmware);
  }

  /**
   * Apply the stack analysis to the given firmware image producing a maximum
   * stack usage (in bytes).
   *
   * @return maxHeight = height of stack.
   */
  public int apply() {
    // Reset the maximum, height
    this.maxHeight = 0;
    // Traverse instructions starting at beginning
    traverse(0, 0);
    // Return the maximum height observed
    return this.maxHeight;
    
  }

  /**
   * Traverse the instruction at a given pc address, assuming the stack has a
   * given height on entry.
   *
   * @param pc            Program Counter of instruction to traverse
   * @param currentHeight Current height of the stack at this point (in bytes)
   */
  private void traverse(int pc, int currentHeight) {
    // Check whether current stack height is maximum
    this.maxHeight = Math.max(this.maxHeight, currentHeight);
    // Check whether we have terminated or not
    if ((pc * 2) >= this.firmware.size()) {
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
   * Process the effect of a given instruction. Switch statement to traverse differently depending 
   * on what the instruction is. 
   *
   * @param instruction   Instruction to process
   * @param pc            Program counter of following instruction
   * @param currentHeight Current height of the stack at this point (in bytes)
   */
  private void process(AvrInstruction instruction, int pc, int currentHeight) {
    switch (instruction.getOpcode()) {
      case BREQ: 
      case BRGE: 
      case BRLT: {
        RelativeAddress branch = (RelativeAddress) instruction;
        if (branch.k != -1 && !previouslyVisited(instruction, currentHeight, pc)) {
          addCurrentValues(instruction, pc, currentHeight);
          int size = this.previousIn.size();
          traverse(pc + branch.k, currentHeight);
          //Once it had traversed down a branch, then remove the instructions
          //that it had seen down that branch
          traverse(pc, currentHeight);
          removeInstructions(size);
        }
        
        break;
      }
      case SBRS: {
        addCurrentValues(instruction, pc, currentHeight);
        int size = this.previousIn.size();
        traverse(pc, currentHeight);
        traverse(pc + 1, currentHeight);
        removeInstructions(size);
        
        break;
      }
      case CALL: {
        AbsoluteAddress branch = (AbsoluteAddress) instruction;
        if (branch.k != -1) {
          addCurrentValues(instruction, pc, currentHeight);
          int size = this.previousIn.size();
          traverse(branch.k, currentHeight + 2);
          removeInstructions(size);
          
          
        }
        addCurrentValues(instruction, pc, currentHeight);
        int size = this.previousIn.size();
        traverse(pc, currentHeight);
        removeInstructions(size);
        
        break;
      }
      case RCALL: {
        RelativeAddress branch = (RelativeAddress) instruction;
        if (branch.k != -1 && !previouslyVisited(instruction, currentHeight, pc)) {
          addCurrentValues(instruction, pc, currentHeight);
          int size = this.previousIn.size();
          traverse(pc + branch.k, currentHeight + 2);
          removeInstructions(size);
        }
        
        addCurrentValues(instruction, pc, currentHeight);
        int size = this.previousIn.size();
        traverse(pc, currentHeight);
        removeInstructions(size);
        
        break;
      }
      case JMP: {
        AbsoluteAddress branch = (AbsoluteAddress) instruction;
        if (branch.k != -1) {
          addCurrentValues(instruction, pc, currentHeight);
          int size = this.previousIn.size();
          traverse(branch.k, currentHeight);
          removeInstructions(size);
          
        }
        break;
      }
      case RJMP: {
        RelativeAddress branch = (RelativeAddress) instruction;
        if (branch.k != -1 && !previouslyVisited(instruction, currentHeight, pc)) {
          addCurrentValues(instruction, pc, currentHeight);
          int size = this.previousIn.size();
          traverse(pc + branch.k, currentHeight);
          removeInstructions(size);
        }
        //
        break;
      }
      case RET:
        break;
      case RETI:
        break;
      case PUSH: {
        addCurrentValues(instruction, pc, currentHeight);
        int size = this.previousIn.size();
        traverse(pc, currentHeight + 1);
        removeInstructions(size);
        
        break;
      }
      case POP: {
        addCurrentValues(instruction, pc, currentHeight);
        int size = this.previousIn.size();
        traverse(pc, currentHeight - 1);
        removeInstructions(size);
        break;
      }
      default: {
        // Indicates a standard instruction where control is transferred to the
        addCurrentValues(instruction, pc, currentHeight);
        int size = this.previousIn.size();
        traverse(pc, currentHeight);
        removeInstructions(size);
      }
    }
  }

  /**
   * Add the current values to the respective lists to keep track of them
   * when moving down a branch. 
   * @param instruction   Instruction to process
   * @param pc            Program counter of following instruction
   * @param currentHeight Current height of the stack at this point (in bytes)
   */
  public void addCurrentValues(AvrInstruction instruction, int pc, int currentHeight) {
    this.previousIn.add(instruction);
    this.previousStackHeight.add(Integer.valueOf(currentHeight));
    this.previousPC.add(Integer.valueOf(pc));
  }
  
  /**
   * Remove the instructions that had been added when moving down a branch.
   * @param size = the point to stop removing instructions
   */
  public void removeInstructions(int size) {
    for (int i = this.previousIn.size() - 1; i > size; i--) {
      this.previousIn.remove(i);
      this.previousStackHeight.remove(i);
      this.previousPC.remove(i);
    }
  }
  
  /**
   * Check if we have already visited this instruction.
   * If the current height is the same, then it is a stable 
   * If the current height is different, then it is unstable. 
   * @param instruction           Current Instruction
   * @param currentHeight Current height of the stack at this point (in bytes)
   * @param pc = Current program counter. 
   * @return = true for seen before, false for not. 
   */
  public boolean previouslyVisited(AvrInstruction instruction, int currentHeight, int pc) {
    //If the maxHeight is MAX_VALUE, then it must have already been seen
    if (this.maxHeight == Integer.MAX_VALUE) {
      return true;
    }
    for (int i = 0; i < this.previousIn.size(); i++) {
      AvrInstruction previous = this.previousIn.get(i);
      int previouspc = this.previousPC.get(i).intValue();
      if (previous.toString().equals(instruction.toString()) && pc == previouspc) {
        int previousHeight = this.previousStackHeight.get(i).intValue();
        //If the currentHeight is the same, in it is stable. 
        if (previousHeight == currentHeight) {
          return true;
        }
        RelativeAddress branch = (RelativeAddress) instruction;
        AvrInstruction instruction2 = decodeInstructionAt(pc + branch.k);
        int next = pc + branch.k + instruction2.getWidth();
        //If the currentHeight is not the same, then it is unstable. 
        if (previousHeight != currentHeight && next < pc) {
          this.maxHeight = Integer.MAX_VALUE;
        }
      }
    }
    return false;
  }
  

  

  /**
   * Decode the instruction at a given PC location.
   *
   * @param pc = program counter. 
   * @return AvrInstruction = set of instructions
   */
  private AvrInstruction decodeInstructionAt(int pc) {
    return this.decoder.decode(this.firmware, pc);
  }
}
