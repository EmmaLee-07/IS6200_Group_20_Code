// SPDX-License-Identifier: MIT
// Specifies the license type, ensuring copyright transparency

/**
 * Compiler version pragma.
 * ^0.8.20 indicates that this contract requires compiler version 0.8.20 or higher (but less than 0.9.0).
 */
pragma solidity ^0.8.20;

/**
 * Imports OpenZeppelin's ReentrancyGuard module.
 * This module provides the `nonReentrant` modifier to prevent "reentrancy attacks."
 * Reentrancy is one of the most common security vulnerabilities in smart contracts, 
 * where an attacker calls back into the contract before the initial execution completes.
 */
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * Freelance Escrow Contract.
 * Inherits from ReentrancyGuard to gain anti-reentrancy capabilities, 
 * ensuring the security of the fund transfer process.
 */
contract FreelanceEscrow is ReentrancyGuard {
    
    /**
     * Defines various states of a task.
     * - None: Default value, indicates task does not exist.
     * - Created: Task created, funds deposited.
     * - Locked: Task locked, designer has started working.
     * - Completed: Task finished normally, funds settled.
     * - Disputed: Dispute occurred, awaiting arbitration.
     * - Resolved: Dispute settled by the arbitrator.
     */
    enum Status { None, Created, Locked, Completed, Disputed, Resolved }


    /**
     * Structure to store details of an individual task.
     */
    struct Task {
        address buyer;  // Address of the buyer (employer)
        address designer;   // Address of the designer (service provider)
        address arbitrator;   // Address of the arbitrator for potential disputes
        uint256 amount;  // Amount of funds held in escrow (in ETH)
        string taskHash;  // Hash of task requirements (typically on IPFS)
        string workHash;    // Hash of the delivered work
        bytes32 prevHash; // Hash of previous task or version for traceability
        Status status;  // Current status of the task
    }
    /**
     * @dev Maps a task ID to its corresponding Task details.
     * @dev Counter for total tasks created; also serves as the unique ID for the next task.
     * @dev Stores the most recent cryptographic hash representing the contract's state for audit trails.
     */
    mapping(uint256 => Task) public tasks; 
    uint256 public taskCount;
    bytes32 public lastContractHash; 

    /**
     * @dev Nested mapping to track votes for a specific task.
     * Structure: taskId => (voter_address => vote_value).
     */
    mapping(uint256 => mapping(address => uint8)) public votes;

    /**
     * @dev Emitted when a new task is initialized and funds are locked in escrow.
     * @param taskId The unique identifier for the task.
     * @param buyer The address of the user who created the task and provided funds.
     * @param amount The total value of funds held in the contract for this task.
     * @param contractHash The updated state hash after this task creation.
     */
    event TaskCreated(uint256 indexed taskId, address buyer, uint256 amount, bytes32 contractHash);
    /**
     * @dev Emitted when funds are released from the escrow to either the designer or the buyer.
     * @param taskId The unique identifier for the task being settled.
     * @param receiver The address receiving the released funds.
     * @param amount The total value of funds transferred.
     * @param contractHash The updated state hash after the settlement.
     */
    event TaskSettled(uint256 indexed taskId, address receiver, uint256 amount, bytes32 contractHash);

    /**
     * @notice Creates a new freelance task and locks the deposited funds in escrow.
     * @dev Increments taskCount and initializes a Task struct.
     * The status is set to 'Locked' immediately, assuming the designer is ready to start.
     * Uses the 'nonReentrant' modifier to prevent recursive calls during fund handling.
     * * @param _designer The address of the service provider who will perform the task.
     * @param _arbitrator The neutral third-party address responsible for resolving disputes.
     * @param _taskHash The IPFS hash or metadata URI containing the task requirements.
     * @return The unique ID (taskCount) assigned to the newly created task.
     */
    function createTask(address _designer, address _arbitrator, string memory _taskHash) external payable nonReentrant returns (uint256) {
        
        require(msg.value > 0, "Must deposit funds"); // Ensure the buyer has sent Ether to be held in escrow
        require(_designer != address(0) && _arbitrator != address(0), "Invalid addresses"); // Prevent setting the burn address as a participant

        taskCount++;
        uint256 currentId = taskCount;

        // Map the new ID to a Task struct with the provided details
        tasks[currentId] = Task({
            buyer: msg.sender, // The caller is the buyer
            designer: _designer,
            arbitrator: _arbitrator,
            amount: msg.value,  // Store the exact amount of Wei received
            taskHash: _taskHash,  
            workHash: "",   // Initialized as empty until the designer submits work         
            prevHash: lastContractHash,   // Links this task to the previous state for auditability
            status: Status.Locked   // Sets the initial workflow state
        });

        _updateGlobalHash("CreateTask", currentId);  // Updates the cryptographic fingerprint of the contract state
        emit TaskCreated(currentId, msg.sender, msg.value, lastContractHash);  // Log the task creation for off-chain indexing (Subgraphs/Front-end)
        return currentId;
    }

    /**
     * @notice Allows the designer to submit their completed work and transition the task status.
     * @dev Updates the 'workHash' with proof of completion (e.g., an IPFS hash) and moves the state to 'Completed'.
     * Uses 'storage' pointer to modify the state of the existing task in the mapping.
     * @param _taskId The unique identifier of the task being worked on.
     * @param _workHash The cryptographic hash or URI pointing to the delivered assets.
     */
    function submitWork(uint256 _taskId, string memory _workHash) external nonReentrant {
        Task storage task = tasks[_taskId]; // Create a reference to the task in contract storage to allow persistent updates
        require(task.buyer != address(0), "Task does not exist"); // Basic validation to ensure the task has been initialized
        require(msg.sender == task.designer, "Only designer can submit"); // Authorization check: Only the assigned designer can call this function
        require(task.status == Status.Locked, "Task not Locked"); // Workflow check: Ensures the task is currently in the 'Locked' state (in progress)

        task.workHash = _workHash; // Record the proof of work
        task.status = Status.Completed;  // Mark the task as completed (Note: This usually triggers fund release logic in a full escrow)
        _updateGlobalHash("SubmitWork", _taskId);  // Update the global state fingerprint for auditability
    }

    /**
     * @notice Allows the buyer to approve the submitted work and release funds to the designer.
     * @dev This is the "happy path" resolution where the buyer is satisfied with the workHash.
     * It triggers the internal settlement mechanism to transfer the escrowed Ether.
     * @param _taskId The unique identifier of the task to be finalized.
     */
    function confirmReceipt(uint256 _taskId) external nonReentrant {
        Task storage task = tasks[_taskId]; // Reference the task from persistent storage
        require(msg.sender == task.buyer, "Only buyer can confirm"); // Authorization check: Only the buyer who funded the task can release the payment
        require(task.status == Status.Completed, "Work not submitted"); // Workflow check: The designer must have called 'submitWork' (setting status to Completed) first

        _executeSettlement(_taskId, task.designer, "ConfirmReceipt"); // Internal call to handle the actual transfer of funds and state cleanup; Passes the designer's address as the recipient of the full task amount
    }

    /**
     * @notice Casts a vote to resolve a dispute between the buyer and the designer.
     * @dev Implements a majority-rule voting system (2 out of 3). 
     * Participants include the buyer, the designer, and the arbitrator.
     * @param _taskId The unique identifier of the task under dispute.
     * @param _decision The vote choice: 1 for Designer (release funds), 2 for Buyer (refund).
     */
    function voteOnDispute(uint256 _taskId, uint8 _decision) external nonReentrant {
        Task storage task = tasks[_taskId]; // Reference the task in storage to check current status and participants
        require(msg.sender == task.buyer || msg.sender == task.designer || msg.sender == task.arbitrator, "Not authorized"); // Authorization: Only the three parties involved in the specific task can vote
        require(_decision == 1 || _decision == 2, "1=Designer, 2=Buyer"); // Validation: Ensure the vote is restricted to valid options
        require(votes[_taskId][msg.sender] == 0, "Voted"); // Anti-Double Voting: Ensure the caller hasn't already cast a vote for this task
        require(task.status != Status.Resolved, "Already settled"); // Integrity Check: Prevent voting on tasks that are already closed/settled

        votes[_taskId][msg.sender] = _decision; // Record the caller's vote in the mapping
        
        uint8 toDesigner = 0; // Tallies for the majority check
        uint8 toBuyer = 0;
        address[3] memory p = [task.buyer, task.designer, task.arbitrator]; // Array of participants to iterate through their specific voting records
        
        // Tallying logic: Checks the 'votes' mapping for each participant
        for (uint i = 0; i < 3; i++) {
            if (votes[_taskId][p[i]] == 1) toDesigner++;
            if (votes[_taskId][p[i]] == 2) toBuyer++;
        }

        //If at least 2 parties agree, the settlement is executed automatically.
        if (toDesigner >= 2) {
            _executeSettlement(_taskId, task.designer, "DisputeResolvedToDesigner");
        } else if (toBuyer >= 2) {
            _executeSettlement(_taskId, task.buyer, "DisputeResolvedToBuyer");
        }
    }

    /**
     * @dev Internal function to handle the actual transfer of funds and update task status.
     * This function centralizes the payout logic to ensure consistency across different
     * resolution paths (Normal completion, Buyer confirmation, or Dispute resolution).
     * @param _taskId The unique identifier of the task to be settled.
     * @param _receiver The address designated to receive the escrowed funds.
     * @param _action A string identifier of the calling action for state tracking.
     */
    function _executeSettlement(uint256 _taskId, address _receiver, string memory _action) internal {
        Task storage task = tasks[_taskId]; // Reference the task in storage to update its final state
        require(task.status != Status.Resolved, "Already settled"); // Re-entrancy/Double-spending protection: Ensure the task isn't already settled
        
        uint256 payment = task.amount; // Local variable to store the amount before resetting the state
        require(payment > 0, "No funds"); // Safety checks to ensure funds exist both in the task record and the contract balance
        require(address(this).balance >= payment, "Insuff balance");

        //State Update (Checks-Effects-Interactions pattern): We update the status and zero out the amount BEFORE the external transfer to prevent potential re-entrancy vulnerabilities.
        task.status = Status.Resolved;
        task.amount = 0; 

        // Low-level call to transfer Ether. Using .call{value: payment}("") is the recommended way to send Ether, as it forwards all available gas and handles potential recipient contract logic.
        (bool success, ) = payable(_receiver).call{value: payment}("");
        require(success, "Transfer failed");

        
        _updateGlobalHash(_action, _taskId); // Update the cryptographic history of the contract
        emit TaskSettled(_taskId, _receiver, payment, lastContractHash); // Emit the settlement event for off-chain monitoring and transparency
    }

    /**
     * @dev Internal function to update the global cryptographic state hash.
     * This creates a "chain of custody" or a "state-link" by hashing the current 
     * action's metadata with the previous hash stored in the contract.
     * @param _action A string describing the function that triggered the update (e.g., "CreateTask").
     * @param _taskId The ID of the task associated with the state change.
     */
    function _updateGlobalHash(string memory _action, uint256 _taskId) internal {
        /**
         * keccak256: The standard Ethereum hashing algorithm.
         * abi.encodePacked: Concatenates the inputs into a byte stream before hashing.
         * * The hash includes:
         * 1. block.timestamp: The current block's time to ensure uniqueness over time.
         * 2. _action: The context of the change.
         * 3. _taskId: The specific data point changed.
         * 4. lastContractHash: The previous state, creating a linked chain of history.
         */
        lastContractHash = keccak256(abi.encodePacked(block.timestamp, _action, _taskId, lastContractHash));
    }
}