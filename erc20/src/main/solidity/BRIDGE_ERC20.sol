// SPDX-License-Identifier: MIT

// ----------------------------------
// Coded by Jesús Sánchez Fernández
// WWW.JSANCHEZFDZ.ES
// ----------------------------------

pragma solidity ^0.8.0;

// ERC-20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Security
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// Utils
import "@openzeppelin/contracts/utils/Strings.sol";


contract BRIDGE_ERC20 is
Ownable,
AccessControlEnumerable,
ReentrancyGuard
{

    using SafeERC20 for IERC20;

    // Contract name
    string public name;

    // Contract symbol
    string public symbol;

    // Smart contract metadata URI
    string private scURI;

    // Payment address
    address private withdrawAddress;

    // WITHDRAWER ROLE
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");
    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");

    constructor(address _withdrawAddress) {
        // Grant role
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        // Withdraw
        withdrawAddress = _withdrawAddress;
    }

    /**********************************************
     **********************************************
                       MODIFIERs
     **********************************************
     **********************************************/

    /**
     * @dev Modifier to make a function callable only when have the DEFAULT_ADMIN_ROLE or OWNER.
     */
    modifier onlyStaff() {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()) ||
            owner() == _msgSender(),
            "Only admins or owner"
        );
        _;
    }

    /**********************************************
     **********************************************
                    SC METADATA
     **********************************************
     **********************************************/

    /**
     * @dev Smart Contract metadata
     * See https://docs.opensea.io/docs/contract-level-metadata
     */
    function contractURI() external view returns (string memory) {
        return scURI;
    }

    /**
     * @dev Change the URI - Smart contract metadata
     * See https://docs.opensea.io/docs/contract-level-metadata
     */
    function setContractURI(string memory _newUri) external onlyStaff {
        scURI = _newUri;
    }

    /**
     * @dev Set the name of the token
     * @param newName string Name of the token
     */
    function setName(string memory newName) public onlyStaff {
        name = newName;
    }

    /**
     * @dev Set the symbol of the token
     * @param newSymbol string Symbol of the token
     */
    function setSymbol(string memory newSymbol) public onlyStaff {
        symbol = newSymbol;
    }

    /***************************
    * ERC-20
    ****************************/

    /**
     * @dev Get balance of the contract
     * @param token Token address
     */
    function getContractTokenBalance(address token) public view returns(uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    /**
     * @dev Withdraw other tokens. Send all selected tokens to payments address.
     * @param token Token address
     */
    function withdraw(address token, uint amount) external nonReentrant {
        require((hasRole(WITHDRAWER_ROLE, _msgSender())), "Only withdrawer role");
        require(withdrawAddress != address(0), "Withdraw address is 0x0");
        IERC20(token).safeTransfer(withdrawAddress, amount);
    }

    function safeTransferFrom(address token, uint amount, address to) external nonReentrant {
        require((hasRole(BRIDGE_ROLE, _msgSender())), "Only BRIDGE");
        IERC20(token).safeTransfer(to, amount);
    }

}
