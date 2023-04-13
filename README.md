A contract for maintaining peg of [ERC1155 tokens](https://eips.ethereum.org/EIPS/eip-1155) to [assets on Ardor](https://ardordocs.jelurida.com/Asset_exchange).
The ERC-1155 tokens are considered a "wrapped" version of the Ardor assets, which exists on the Ethereum or some other
EVM-compatible network.

## Peg Initialization

### 1. Get an Ethereum full node
Install and sync an Ethereum full node or register with [Infura](https://infura.io/) or other similar provider.
Other EVM-compatible networks are also supported.

### 2. ERC1155 tokens minting
Skip this step if [auto-minting](#612-auto-minting) is going to be enabled

For each asset which is going to be wrapped, mint a token with some [ERC1155-compatible](https://eips.ethereum.org/EIPS/eip-1155) 
Ethereum contract. The amount of the minted ERC1155 tokens must not exceed the asset quantity in circulation on the 
Ardor platform.

### 3. Install Ardor

### 4. Handle the missing dependencies
 * Run the `exportLibsMissingInArdor` task in this project:
```
./gradlew exportLibsMissingInArdor
```
 * Copy the libraries from `contract/libs-exported` to the `lib` directory inside the Ardor installation directory.

### 5. Configure the Ardor node for running the contract
Add
```
nxt.addOns=nxt.addons.ContractRunner
nxt.disableSecurityPolicy=true
```
to [the `nxt.properties` of the Ardor installation](https://ardordocs.jelurida.com/Faq#Node_configuration_using_the_nxt.properties)

**Warning**\
Allowing connections to the Ardor node from outside its local machine is a bad idea. The `triggerContractByRequest` API,
which is used to execute [commands to the peg contract](#commands-reference), is [password protected](https://ardordocs.jelurida.com/API#Admin_Password).
So executing any command requires the caller to have the [Ardor node adminPassword](https://ardordocs.jelurida.com/API#Admin_Password),
which means that he can modify the Ardor node in many ways including getting DB access to it.\
The recommended approach is to develop a small proxy backed which to run on the same server as the Ardor node and which
to expose only the [getUnwrapDepositAddress](#getunwrapdepositaddress) and [processUnwrapsForAccount](#processunwrapsforaccount)
commands.\
Additionally, with Infura all requests to the Ethereum API are counted against a quota. The 
[processUnwrapsForAccount](#processunwrapsforaccount) command calls the Ethereum API even if there is no unwrap
transfer to execute. So if using Infura, the backend must also implement some restriction on the calls to 
[processUnwrapsForAccount](#processunwrapsforaccount).

### 6. Create Contract Runner configuration
The configuration is a JSON file - check `contract/src/test/resources/test_contract_config.json` for an example.

#### 6.1 Secrets
Generate strong secrets for `ethereumDepositAccountsSecret`, `ethereumBlockedAccountSecret` and 
the contract account, which will act as Ardor Blocked Account - will own all locked tokens which are in circulation on 
Ethereum side. Set `ethereumDepositAccountsSecret` and `ethereumBlockedAccountSecret` to the
generated values.

#### 6.2 `accountRS`
Set in `accountRS` the [address](https://ardordocs.jelurida.com/RS_Address_Format) of the Ardor Blocked Account. To 
get the address login with the generated Ardor passphrase.

#### 6.3 `apiUrl`
Set in `apiUrl` the URL of the HTTP API of your Ethereum full node. Other EVM-compatible networks like Polygon
are also supported.

#### 6.4
Set in `chainId` the chain ID of the Ethereum network as required by [ERC-155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md).
A list of the chain IDs of the popular EVN-compatible networks is available [here](https://chainlist.org/)

#### 6.5 Configure eth_getLogs calls

##### 6.5.1 `ethLogsBlockRange`
Set in `ethLogsBlockRange` the max size of the block range allowed by the Ethereum full node when calling eth_getLogs.
  Value of 0 makes all eth_getLogs requests to be executed from the first to the latest block in the blockchain.

##### 6.5.2 `ethLogsIterations`
Set `ethLogsIterations` to more than `1` to execute the calls to eth_getLogs in a loop. Each call will cover a subsequent
block range of `ethLogsBlockRange`. Use this in case the full node has an unacceptable limit on the block range. 
The downside is that `ethLogsIterations` requests will be made when getting the logs in order to check for pending 
unwrapping or already processed wrappings.
Make sure that `ethLogsBlockRange` * `ethLogsIterations` * `average_block_time` is at least 5-6 hours to allow users 
to process their unwrapping deposits.

#### 6.6 Confirmations
Adjust `ardorConfirmations` and `ethereumConfirmations` - these are the number of blocks that the peg contract will
  wait before considering a transaction confirmed.

#### 6.7 Fast Wrapping
[Fast wrapping](#fast-wrapping) is enabled if `fastWrappingConfirmations` is set to less than `ardorConfirmations`.

##### 6.7.1 `fastWrappingMinDeadline`
If [Fast wrapping](#fast-wrapping) is enabled, set in `fastWrappingMinDeadline` the minimal transaction deadline
  required for the transaction to be eligible for fast wrapping

#### 6.8 Ardor Fees
`ardorInitialFeeOverpayPercent` and `ardorRetryFeeOverpayPercent` are percentages with which to increase the Ardor 
transaction fee initially and each time a transaction expires without being accepted in a block. The default 
transactions deadline is 15 min. `ardorInitialFeeOverpayPercent` is a string and may be negative in which case the
initial fee is below the automatically calculated by the node fee

#### 6.9 `ethereumRetryTimeout`
Time in seconds to wait for ethereum transaction to be accepted in a block before retrying
with higher fee

#### 6.10 Ethereum Fees
`ethereumGasPriceInitialOverpay` and `ethereumGasPriceRetryOverpay` are percentages with which to increase the Ethereum
transaction fee initially and each time a transaction is not accepted before `ethereumRetryTimeout`.
`ethereumGasPriceInitialOverpay` is string and may be negative in which case the starting gas price is below the one
calculated by the Ethereum node

#### 6.11 `contractAddress`
Set in `contractAddress` the address of the contract which will manage the wrapped assets on Ethereum side. For 
example the contract address of OpenSea on Polygon Mumbai testnet is `0x2953399124F0cBB46d2CbACD8A89cF0599974963`

#### 6.12 Auto-minting
To enable the auto-minting of wrapping ERC1155 tokens, set `autoMintErc1155` to `true`. When auto-minting is enabled,
the tokens on ethereum side are automatically minted when a wrapping is complete and burned when un-wrapping is complete.
For this, the contract specified in `contractAddress` must implement the 
[IERC1155MintBurn](erc1155/src/main/solidity/IERC1155MintBurn.sol) interface. 
Use the [deployEthContract](#deployethcontract) command before `contractAddress` is set to deploy a basic 
implementation of such auto-mintable contract provided in 
[erc1155/src/main/solidity/ERC1155MintBurn.sol](erc1155/src/main/solidity/ERC1155MintBurn.sol).
Then set the ID of the deployed contract in `contractAddress`

##### 6.12.1 `autoMintWhitelistedIssuers`
If auto-minting is **enabled**, set in `autoMintWhitelistedIssuers` a list of Ardor account IDs specifying the asset
issuers whose assets will be processed by `AssetsErc1155Peg`

#### 6.13 `assetIdToErc1155IdMap`
If auto-minting is **disabled**, set in `assetIdToErc1155IdMap` a JSON object mapping between the known asset IDs on 
Ardor and the ERC1155 tokens IDs.
The JSON keys must contain asset IDs as unsigned integer strings.
The values must contain the corresponding ERC1155 token IDs as unsigned integer string, or a string with format '0x' 
followed by up to 64 hex chars (32 bytes in hex format). Example:
```
"assetIdToErc1155IdMap": {
  "6433412706225592098": "0xd1a49a09d7d1be11108f2629859695aec32f3e2b00000000594812c5480f9722"
}
```

### 7. Start and configure the Contract Runner
Start Ardor and set the configuration built on [step 6](#6-create-contract-runner-configuration).
See [How to configure the Contract Runner](https://ardordocs.jelurida.com/Lightweight_Contracts#How_to_configure_the_Contract_Runner) 
and use the Node Processes UI in order to utilize the encryption supported by it.

If [auto-minting](#612-auto-minting) is enabled, start Ardor with empty 
`contractAddress`, execute the [deployEthContract](#deployethcontract) command, set the result in `contractAddress` 
and restart Ardor.

### 8. Deploy the `AssetsErc1155Peg` contract.
Can be done by executing the `deployContract` gradle task:
```
./gradlew deployContract
```
The task reads [the Contract Manager configuration](https://ardordocs.jelurida.com/Lightweight_Contracts#Contract_Manager)
from `contract/conf/nxt-deployContract.properties` - create this file and set at least the 
`contract.manager.secretPhrase` property to the previously generated secret of the Ardor Blocked Account.
The deployment can be executed remotely by setting the `contract.manager.serverAddress` property. 

Make sure the Ardor Blocked Account secret is secured - delete it from `nxt-deployContract.properties` or delete the
whole file. This file is used only by the `deployContract` task.

### 9. Get the peg addresses

This step can be skipped if [auto-minting](#612-auto-minting) is enabled

With the Contract Runner started on the Ardor node, call the `triggerContractByRequest` API with command `getPegAddresses`:
```shell
curl 'http://localhost:26876/nxt?requestType=triggerContractByRequest&contractName=AssetsErc1155Peg&command=getPegAddresses' 
```
You should get a response like 

```json
{
  "ardorBlockedAccount": "ARDOR-J24K-QWD8-XHEX-36P7X",
  "ethereumBlockedAccount": "0xd1a49a09d7d1be11108f2629859695aec32f3e2b",
  "requestProcessingTime": 0
}
```
See the [Commands Reference](#commands-reference) section for more details about the available commands.

### 10. Transfer all minted ERC-1155 tokens to the Ethereum Blocked Account.

Skip this step if [auto-minting](#612-auto-minting) is enabled

The Ethereum Blocked Account address is returned in `ethereumBlockedAccount` on [step 9](#9-get-the-peg-addresses)

### Done

This way the peg contract is initialized in fully unwrapped state - all tokens are in circulation on Ardor side and can
be wrapped into ERC-1155 tokens.

Alternatively if all Ardor assets are transferred to the `ardorBlockedAccount` on
[step 10](#10-transfer-all-minted-erc-1155-tokens-to-the-ethereum-blocked-account), and the ERC-1155 tokens are released
in circulation on Ethereum side, the contract will be in "fully wrapped" state (this is valid only if 
[auto-minting](#612-auto-minting) is **disabled**)

## Wrapping

If [auto-minting](#612-auto-minting) is **enabled**, wrapping happens when any asset issued by 
some of the accounts in the [`autoMintWhitelistedIssuers` list](#6121-automintwhitelistedissuers) is 
transferred to the Ardor Blocked Account. The result is a freshly minted ERC-1155 token on Ethereum side with ID 
equal to the asset ID.

If [auto-minting](#612-auto-minting) is **disabled**, wrapping happens when an asset, which is
supported according to the [`assetIdToErc1155IdMap` configuration](#613-assetidtoerc1155idmap), is 
transferred to the Ardor Blocked Account.

The asset transfer transaction must contain in its message the [Ethereum address](https://en.wikipedia.org/wiki/Ethereum#Addresses) 
which to receive the wrapped tokens. It is recommended to use the [Encrypted Message functionality in Ardor](https://ardordocs.jelurida.com/Arbitrary_messages/en#Sending_an_encrypted_message)
 in order to preserve privacy.

Special care must be taken to not process some wrapping transactions twice. So the contract processes only the
transactions in blocks generated during its execution. Any older blocks must be manually processed by executing the
[processWrapsAtHeight](#processwrapsatheight) command.

### Fast wrapping

A fast wrapping option is available in case the pegged tokens don't have significant economic value. If enabled,
the wrapping transactions are confirmed after fewer blocks (configurable via 
[`fastWrappingConfirmations`](#67-fast-wrapping)) if the following conditions are met:

* The transaction deadline is greater than [`fastWrappingMinDeadline`](#671-fastwrappingmindeadline)
* The transaction Economic Clustering (EC) block is more than [`ardorConfirmations`](#66-confirmations)
blocks before the transaction height
* The transaction is not phased
* The transaction is not referencing other transaction

These restrictions are meant to reduce the chances for a transaction to become invalid in case of spontaneous blockchain
reorganization. An attacker with enough forging power can still invalidate such transaction and do a double spend.
So the fast confirmation mode must be used only for low-value assets.

## Unwrapping

Unwrapping is triggered by a call to [processUnwrapsForAccount](#processunwrapsforaccount), but before this call the
tokens to unwrap must be transferred to an UnwrapDepositAccount - an Ethereum account dedicated to and generated for 
the Ardor account which will receive the unwrapped assets.

To get the UnwrapDepositAccount address use the [getUnwrapDepositAddress](#getunwrapdepositaddress) command.

## Commands Reference
The `AssetsErc1155Peg` supports several commands through the `triggerContractByRequest` [Ardor API](https://ardordocs.jelurida.com/API).

In all cases the `contractName` parameter of that API must be set to `AssetsErc1155Peg`.

The rest of the parameters can be provided either as JSON object in the `setupParams` parameter, or as separate parameters.

A mandatory `command` parameter is used to distinguish the different operations supported by `AssetsErc1155Peg`. Each
command has its own set of additional parameters. The following sub-sections contain a reference of the supported commands

### getPegAddresses
Returns the addresses of Ardor Blocked Account and Ethereum Blocked Account.

#### No parameters required
 
#### Response

```json5
{
  "ardorBlockedAccount": "ARDOR-...", // The address of the Ardor Blocked Account
  "ethereumBlockedAccount": "0x..."// The address of the Ethereum Blocked Account
}
```

### getUnwrapDepositAddress
Returns the address for depositing ERC-1155 tokens in order to unwrap them back to Ardor. This address is specific for
each Ardor account.

#### Parameters
* `ardorRecipientPublicKey` The public key of the Ardor account for which an address for unwrapping is generated

#### Response
```json5
{
"depositAddress": "0x..." //An Ethereum address
}
```

### processUnwrapsForAccount
1. Calculate the UnwrapDepositAccount similarly to [getUnwrapDepositAddress](#getunwrapdepositaddress)
2. Gets all transfers to the UnwrapDepositAccount in the last 100000 blocks
3. Filter out any transfers for which the unwrapping is currently being processed or is completed
4. Start a background unwrap task for any transfers left

#### Parameters
* `ardorRecipientPublicKey` The public key of the Ardor account to which to send the unwrapped tokens

#### Response
A JSON object with the number of tasks started or filtered out transfers by filter category. Fields with value 0 are
not returned
```json5
{
  "starts": 0123456789, //Number of tasks started by the current request
  "skippedAlreadyPending": 0123456789, //Transfers skipped during the request because there is already a background task processing them
  "skippedCompleted": 0123456789, //Transfers which were already completed and there is an outgoing Ardor transaction for them
  "unknownTokens": 0123456789 // Transfers of tokens not in the assetIdToErc1155IdMap configuration
}
```

### processWrapsAtHeight

Utility command to manually process the wrapping at some height. There is no check about whether the transactions at
this height were already processed, so special care must be taken to not process same asset transfers twice.

This command returns before the transaction was confirmed on Ethereum side. Use the [getWrappingLog](#getwrappinglog)
command to poll the final result of the wrapping

#### Parameters
 * `height` Height of the ardor blockchain for which to process the wrappings

#### Response
```json5
{
    "transactionsLog": [ //An array of objects
        {
            "fullHash": "...", //fullHash of the Ardor transaction which transfers assets to the Ardor Blocked Account and triggered the wrapping
            "error": "...", //Error message in case of error before the transfer was initiated on Ethereum side
        }
    ],
    "requestProcessingTime": 4
}
```

### getWrappingLog

Returns a log of all wrappings processed during the current execution of the contract.

#### No additional parameters

#### Response
```json5
{
    "log": [
        {
            "fullHash": "...", //fullHash of the Ardor transaction which transfers assets to the Ardor Blocked Account and triggered the wrapping
            "error": "...", //In case the wrap failed
            "success": "0x..." //Transaction ID on Ethereum side
        }
    ],
    "requestProcessingTime": 2
}
```

### secretToEthPrivateKey

Utility for computing the ethereum private key from secret string. The private key can then
be imported in e.g. Metamask.

To get the private key of an unwrapping deposit account, concatenate `ethereumDepositAccountsSecret` 
from [the peg configuration](#6-create-contract-runner-configuration) and the ardor public key of the 
account. For example if `ethereumDepositAccountsSecret` is
```
harmony repeat ourselves woman empty outside liquid truth journey shiver mention curl
```

and the public key of the account is

```
0507916d19b81d9f714c4f9eaf7ad4742b013c106c34cb9d2fb663d5e101df75
```

Then the `secret` parameter should be 

```
harmony repeat ourselves woman empty outside liquid truth journey shiver mention curl0507916d19b81d9f714c4f9eaf7ad4742b013c106c34cb9d2fb663d5e101df75
```

#### Parameters
 * `secret` A string

#### Response
```json5
{
  "privateKeyHex": "0x...", //Private key in hex format. This can be used with Metamask
  "privateKeyNumeric": "..." //Same private key as decimal string 
}
```

### autoMintIdConvert

Utility for converting between the decimal asset IDs used in Ardor to hexadecimal format, primarily used in Ethereum.
Even though the IDs of the [auto-minted](#612-auto-minting) Ethereum tokens which wrap the Ardor 
assets are equal to the Ardor asset ID, in some cases, for example when [ERC1155 metadata](https://eips.ethereum.org/EIPS/eip-1155#metadata)
is handled, the ID is needed in hexadecimal format. This command simply converts from decimal to hexadecimal or vice
versa.

#### Parameters
 * `assetId` ID in decimal format as used in Ardor
OR
 * `tokenId` ID in hexadecimal format as appearing in Ethereum. The "0x" prefix is optional

#### Response
If `assetId` is provided:
```json5
{
  
  "tokenIdHex": "0x...", //hex string
  "erc1155MetadataId": "0000000000000000000000000000000000000000000000000123456789abcdef...", //0-padded hex string as expected by the metadata specification
  "requestProcessingTime": 1
}
```
Or if `tokenId` is provided:
```json5
{
  "assetId": "...", //Ardor asset ID as unsigned decimal string
  "requestProcessingTime": 1
}
```

### checkPegInvariant

Checks the peg invariant: the tokens in circulation on ethereum side must be present as assets in the Ardor Blocked
Account

#### Parameters
* `isOpenSea` Set to "true" if the Ethereum contract is the OpenSea one because that particular contract doesn't implement
the `IERC1155Supply` interface and returns only the tokens in circulation instead of all minted tokens 

#### Response
```json5
{
  "notBackedUpAssets": {
    "<asset id>": {
      "ethTokenIdNum": "...", //Eth token id in numeric format
      "ethTokenIdHex": "0x...", //Eth token id in hex
      "ethTokensInCirculation": "???", //Tokens in circulation on Ethereum side
      "totalSupply": "???", //All minted tokens. Equal to ethTokensInCirculation when autoMintErc1155 is true 
      "abaAssetQty": "???" //Amount available in the Ardor Blocked Account
    }, //one or more objects for each asset for which the invariant check failed
  },
  "backedUpAssets": {
    "<asset id>": {
      "ethTokenIdNum": "...", //Eth token id in numeric format
      "ethTokenIdHex": "0x...", //Eth token id in hex
      "ethTokensInCirculation": "???", //Tokens in circulation on Ethereum side
      "totalSupply": "???", //All minted tokens. Equal to ethTokensInCirculation when autoMintErc1155 is true 
      "abaAssetQty": "???" //Amount available in the Ardor Blocked Account
    }, //one or more objects for each asset for which the invariant check succeeded
  },
"requestProcessingTime": 15009,
"error": "..." //"Some tokens in circulation are not backed" if the invariant failed. Or other error if the call was not successful 
}
```

### deployEthContract

Deploys a contract specifically developed to support auto-minting of ERC1155 tokens for wrapping Ardor assets.

To prevent abuse or errors, this API is available only if the [contractAddress](#611-contractaddress) 
is empty

#### Parameters
 * `uri` The URI which will be returned by the contract to clients for getting tokens metadata. 
See [the ERC1155 metadata specification](https://eips.ethereum.org/EIPS/eip-1155#metadata)

#### Response
```json5
{
  "ethContractAddress":"0x54c8d419a5b9d2d6ff68ff826258456ee37e214b",
  "requestProcessingTime":16743
}
```