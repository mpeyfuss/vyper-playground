# @title ERC721_MP
# @author Marco Peyfuss
# @notice A Transient Labs Implementation of ERC721 in Vyper
# @dev ERC721 with merkle tree allowlist, public option, admin execution priveledges, and on-chain royalties
# @license MIT
# @version ^0.3.0

### Interfaces###
from vyper.interfaces import ERC165
from vyper.interfaces import ERC721
from vyper.interfaces import ERC20

# @dev interface for EIP 2981
interface EIP2981:
    def royaltyInfo(
        _tokenId: uint256,
        _salePrice: uint256,
    ) -> (address, uint256): view

# @dev interface for checking if receiver can receive ERC721 tokens during safeTransferFrom
interface ERC721Receiver:
    def onERC721Received(
            _operator: address,
            _from: address,
            _tokenId: uint256,
            _data: Bytes[1024]
        ) -> bytes4: view

implements: ERC165
implements: ERC721
implements: EIP2981

### Events ###
# @dev Emits when ownership of any NFT changes by any mechanism. This event emits when NFTs are
#   created (`from` == 0) and destroyed (`to` == 0). Exception: during contract creation, any
#   number of NFTs may be created and assigned without emitting Transfer. At the time of any
#   transfer, the approved address for that NFT (if any) is reset to none.
# @param _from Sender of NFT (if address is zero address it indicates token creation).
# @param _to Receiver of NFT (if address is zero address it indicates token destruction).
# @param _tokenId The NFT that got transfered.
event Transfer:
    _from: indexed(address)
    _to: indexed(address)
    _tokenId: indexed(uint256)

# @dev This emits when the approved address for an NFT is changed or reaffirmed. The zero
#   address indicates there is no approved address. When a Transfer event emits, this also
#   indicates that the approved address for that NFT (if any) is reset to none.
# @param _owner Owner of NFT.
# @param _approved Address approved during tx.
# @param _tokenId NFT which is approved.
event Approval:
    _owner: indexed(address)
    _approved: indexed(address)
    _tokenId: indexed(uint256)

# @dev This emits when an operator is enabled or disabled for an owner. The operator can manage
#   all NFTs of the owner.
# @param _owner Owner of NFT.
# @param _operator Address which gets operator rights.
# @param _approved Status of operator rights(true if operator rights are given and false if
#   revoked).
event ApprovalForAll:
    _owner: indexed(address)
    _operator: indexed(address)
    _approved: bool

### Storage Variables ###
# @dev Static list of supported ERC165 interface ids
SUPPORTED_INTERFACES: constant(bytes4[4]) = [
    # ERC165 interface ID of ERC165
    0x01ffc9a7,
    # ERC165 interface ID of ERC721
    0x80ac58cd,
    # ERC165 interface ID of ERC721 Metadata Extension
    0x5b5e139f,
    # ERC165 interface ID of EIP2981
    0x2a55205a,
]

# @dev name of the contract
contract_name: String[20]

# @dev symbol for the contract
contract_symbol: String[10]

# @dev mapping from token id to owner address
id_to_owner: HashMap[uint256, address]

# @dev mapping from owner to token balance
owner_to_balance: HashMap[address, uint256]

# @dev mapping from token id to approved address
id_to_approval: HashMap[uint256, address]

# @dev mapping from owner address to operator
owner_to_operator: HashMap[address, HashMap[address, bool]]

# @dev token counter
counter: uint256

# @dev royalty percentage, out of 10,000
royalty_perc: public(uint256)

# @dev royalty payout address
royalty_addr: public(address)

# @dev admin address
admin: public(address)

# @dev owner address
owner: public(address)

# @dev payout address
payout: public(address)

# @dev mint allowance
mint_allowance: public(uint256)

# @dev total supply
totalSupply: public(uint256)

# @dev allowlist merkle root
merkle_root: immutable(bytes32)

# @dev allowlist sale open boolean
is_presale_open: public(bool)

# @dev public sale open boolean
is_public_sale_open: public(bool)

# @dev mint price
mint_price: public(uint256)

# @dev mapping from address to number minted
num_minted: HashMap[address, uint256]

# @dev base uri for tokens
base_uri: String[100]

### Constructor ###
@external
def __init__(
    _name: String[20],
    _symbol: String[10],
    _supply: uint256,
    _price: uint256,
    _allowance: uint256,
    _merkle_root: bytes32,
    _admin: address,
    _payout: address,
    _royalty_perc: uint256,
    _royalty_addr: address
    ):
        self.contract_name = _name
        self.contract_symbol = _symbol
        self.totalSupply = _supply
        self.mint_price = _price
        self.mint_allowance = _allowance
        merkle_root = _merkle_root
        self.owner = msg.sender
        self.admin = _admin
        self.payout = _payout
        self.royalty_perc = _royalty_perc
        self.royalty_addr = _royalty_addr

### ERC721 Functions ###
@view
@internal
def _exists(_tokenId: uint256) -> bool:
    # @dev returns whether the specified token id exists or not
    # @param _tokenId id of the token in query
    # @return bool indicating if exists
    return self.id_to_owner[_tokenId] != ZERO_ADDRESS

@view
@internal
def _is_approved_or_owner(_spender: address, _tokenId: uint256) -> bool:
    # @dev helper function to determine if the spender is approved or the owner of the NFT
    # @param _spender address of the spender in query
    # @param _tokenId id of the token in query
    # @return bool indicating if approved or owner
    token_owner: address = self.id_to_owner[_tokenId]
    return _spender == token_owner or _spender == self.id_to_approval[_tokenId] or self.owner_to_operator[token_owner][_spender]

@internal
def _approve(_approved: address, _tokenId: uint256):
    # @notice Change or reaffirm the approved address for an NFT
    # @dev The zero address indicates there is no approved address.
    # @param _approved The new approved NFT controller
    # @param _tokenId The NFT to approve
    self.id_to_approval[_tokenId] = _approved
    log Approval(self.id_to_owner[_tokenId], _approved, _tokenId)

@internal
def _transfer(_sender: address, _from: address, _to: address, _tokenId: uint256):
    # @dev executes an NFT transfer
    #   Throws if msg.sender is not the owner or approved
    #   Throws if _from isn't the current NFT holder
    #   Throws if _to is the zero address
    #   Throws if _tokenId doesn't exist
    assert self._exists(_tokenId), "ERC721: Transfer of non-existent token"
    assert self._is_approved_or_owner(_sender, _tokenId), "ERC721: Caller is not owner or approved for transfer"
    assert _from == self.id_to_owner[_tokenId], "ERC721: _from is not the NFT owner"
    assert _to != ZERO_ADDRESS, "ERC721: Transfer to zero address not allowed"

    # clear approvals
    self._approve(ZERO_ADDRESS, _tokenId)

    # update balances and owner
    self.owner_to_balance[_from] -= 1
    self.owner_to_balance[_to] += 1
    self.id_to_owner[_tokenId] = _to

    log Transfer(_from, _to, _tokenId)

@view
@internal
def _check_on_ERC721_received(_from: address, _to: address, _tokenId: uint256, _data: Bytes[1024]) -> bool:
    # @dev executes {IERC721Receiver-onERC721Received} check on the recipient
    # @dev does not execute if _to is not a contract
    # @param from address representing the previous owner of the given token ID
    # @param to target address that will receive the tokens
    # @param tokenId uint256 ID of the token to be transferred
    # @param data bytes optional data to send along with the call
    # @return bool whether the call correctly returned the expected magic value
    tf: bool = True
    if _to.is_contract:
        return_val: bytes4 = ERC721Receiver(_to).onERC721Received(_from, _to, _tokenId, _data)
        tf = return_val == convert(method_id("onERC721Received(address,address,uint256,bytes)", output_type=bytes32), bytes4)
    return tf

@internal
def _mint(_to: address, _tokenId: uint256):
    # @dev mints to address
    # @dev throws if _tokenId has already been minted
    # @dev throws if _to is the zero address
    # @param _to is the recipient
    # @param _tokenId is the token to mint
    assert not self._exists(_tokenId), "ERC721: Token already minted"
    assert _to != ZERO_ADDRESS, "ERC721: Cannot mint to zero address"

    self.owner_to_balance[_to] += 1
    self.id_to_owner[_tokenId] = _to

    log Transfer(ZERO_ADDRESS, _to, _tokenId)

@internal
def _safe_mint(_to: address, _tokenId: uint256):
    # @dev mints and checks if the receiver can receive ERC721 tokens
    self._mint(_to, _tokenId)
    assert self._check_on_ERC721_received(ZERO_ADDRESS, _to, _tokenId, b""), "ERC721: Receiver does not implement IERC721Receiver"

@internal
def _burn(_tokenId: uint256):
    # @dev Burns a specific ERC721 token.
    #    Throws unless `msg.sender` is the current owner, an authorized operator, or the approved
    #    address for this NFT.
    #    Throws if `_tokenId` is not a valid NFT.
    # @param _tokenId uint256 id of the ERC721 token to be burned.
    assert self._exists(_tokenId), "ERC721: Non-existent token"
    assert self._is_approved_or_owner(msg.sender, _tokenId), "ERC721: Caller is not approved or owner"
    token_owner: address = self.id_to_owner[_tokenId]

    # clear approvals
    self._approve(ZERO_ADDRESS, _tokenId)

    # update balances and owner
    self.owner_to_balance[token_owner] -= 1
    self.id_to_owner[_tokenId] = ZERO_ADDRESS

    log Transfer(token_owner, ZERO_ADDRESS, _tokenId)

@view
@external
def balanceOf(_owner: address) -> uint256:
    # @notice Count all NFTs assigned to an owner
    # @dev NFTs assigned to the zero address are considered invalid, and this
    #   function throws for queries about the zero address.
    # @param _owner An address for whom to query the balance
    # @return The number of NFTs owned by `_owner`, possibly zero
    assert _owner != ZERO_ADDRESS, "ERC721: Query for zero address"
    return self.owner_to_balance[_owner]

@view
@external
def ownerOf(_tokenId: uint256) -> address:
    # @notice Find the owner of an NFT
    # @dev NFTs assigned to zero address are considered invalid, and queries
    #     about them do throw.
    # @param _tokenId The identifier for an NFT
    # @return The address of the owner of the NFT
    token_owner: address = self.id_to_owner[_tokenId]
    assert token_owner != ZERO_ADDRESS, "ERC721: Non-existent token query"
    return token_owner

@payable
@external
def safeTransferFrom(_from: address, _to: address, _tokenId: uint256, data: Bytes[1024] = b""):
    # @notice Transfers the ownership of an NFT from one address to another address
    # @dev Throws unless `msg.sender` is the current owner, an authorized
    #     operator, or the approved address for this NFT. Throws if `_from` is
    #     not the current owner. Throws if `_to` is the zero address. Throws if
    #     `_tokenId` is not a valid NFT. When transfer is complete, this function
    #     checks if `_to` is a smart contract (code size > 0). If so, it calls
    #     `onERC721Received` on `_to` and throws if the return value is not
    #     `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.
    # @param _from The current owner of the NFT
    # @param _to The new owner
    # @param _tokenId The NFT to transfer
    # @param data Additional data with no specified format, sent in call to `_to`
    self._transfer(msg.sender, _from, _to, _tokenId)
    assert self._check_on_ERC721_received(_from, _to, _tokenId, data), "ERC721: Receiver does not implement IERC721Receiver"

@payable
@external
def transferFrom(_from: address, _to: address, _tokenId: uint256):
    # @notice Transfer ownership of an NFT -- THE CALLER IS RESPONSIBLE
    #     TO CONFIRM THAT `_to` IS CAPABLE OF RECEIVING NFTS OR ELSE
    #     THEY MAY BE PERMANENTLY LOST
    # @dev Throws unless `msg.sender` is the current owner, an authorized
    #     operator, or the approved address for this NFT. Throws if `_from` is
    #     not the current owner. Throws if `_to` is the zero address. Throws if
    #     `_tokenId` is not a valid NFT.
    # @param _from The current owner of the NFT
    # @param _to The new owner
    # @param _tokenId The NFT to transfer
    self._transfer(msg.sender, _from, _to, _tokenId)

@payable
@external
def approve(_approved: address, _tokenId: uint256):
    # @notice Change or reaffirm the approved address for an NFT
    # @dev The zero address indicates there is no approved address.
    #     Throws unless `msg.sender` is the current NFT owner, or an authorized
    #     operator of the current owner.
    # @param _approved The new approved NFT controller
    # @param _tokenId The NFT to approve
    token_owner: address = self.id_to_owner[_tokenId]
    assert _approved != token_owner, "ERC721: approved address cannot be token owner"
    assert msg.sender == token_owner or self.owner_to_operator[token_owner][msg.sender], "ERC721: caller must be token owner or operator"
    self._approve(_approved, _tokenId)

@external
def setApprovalForAll(_operator: address, _approved: bool):
    # @notice Enable or disable approval for a third party ("operator") to manage
    #     all of `msg.sender`'s assets
    # @dev Emits the ApprovalForAll event. The contract MUST allow
    #     multiple operators per owner.
    # @dev this is not cleared during a token transfer
    # @param _operator Address to add to the set of authorized operators
    # @param _approved True if the operator is approved, false to revoke approval
    assert msg.sender != _operator, "ERC721: message sender cannot be operator"
    self.owner_to_operator[msg.sender][_operator] = _approved

    log ApprovalForAll(msg.sender, _operator, _approved)

@view
@external
def getApproved(_tokenId: uint256) -> address:
    # @notice Get the approved address for a single NFT
    # @dev Throws if `_tokenId` is not a valid NFT.
    # @param _tokenId The NFT to find the approved address for
    # @return The approved address for this NFT, or the zero address if there is none
    assert self._exists(_tokenId), "ERC721: Query for non-existent token"
    return self.id_to_approval[_tokenId]

@view
@external
def isApprovedForAll(_owner: address, _operator: address) -> bool:
    # @notice Query if an address is an authorized operator for another address
    # @param _owner The address that owns the NFTs
    # @param _operator The address that acts on behalf of the owner
    # @return True if `_operator` is an approved operator for `_owner`, false otherwise
    return self.owner_to_operator[_owner][_operator]

### ERC721 Metadata Functions ###
@view
@external
def name() -> String[20]:
    # @notice A descriptive name for a collection of NFTs in this contract
    return self.contract_name

@view
@external
def symbol() -> String[10]:
    # @notice An abbreviated name for NFTs in this contract
    return self.contract_symbol

@view
@external
def tokenURI(_tokenId: uint256) -> String[1024]:
    # @notice A distinct Uniform Resource Identifier (URI) for a given asset.
    # @dev Throws if `_tokenId` is not a valid NFT. URIs are defined in RFC
    #     3986. The URI may point to a JSON file that conforms to the "ERC721
    #     Metadata JSON Schema".
    assert self._exists(_tokenId), "ERC721 Metadata: Query for non-existent token"
    return convert(_abi_encode(self.base_uri, _tokenId), String[1024])

### EIP2981 Functions ###
@view
@external
def royaltyInfo(_tokenId: uint256, _salePrice: uint256) -> (address, uint256):
    # @notice Called with the sale price to determine how much royalty
    #   is owed and to whom.
    # @param _tokenId - the NFT asset queried for royalty information
    # @param _salePrice - the sale price of the NFT asset specified by _tokenId
    # @return receiver - address of who should be sent the royalty payment
    # @return royaltyAmount - the royalty payment amount for _salePrice
    if self._exists(_tokenId) and self.royalty_perc < 10000:
        return (self.royalty_addr, _salePrice*self.royalty_perc/10000)
    else:
        return (ZERO_ADDRESS, 0)

### ERC165 Functions ###
@view
@external
def supportsInterface(interfaceID: bytes4) -> bool:
    # @notice Query if a contract implements an interface
    # @param interfaceID The interface identifier, as specified in ERC-165
    # @dev Interface identification is specified in ERC-165. This function
    #   uses less than 30,000 gas.
    # @return `true` if the contract implements `interfaceID` and
    #   `interfaceID` is not 0xffffffff, `false` otherwise
    return interfaceID in SUPPORTED_INTERFACES and interfaceID != 0xffffffff

### TL Functions ###
@view
@internal
def _is_admin_or_owner(_sender: address) -> bool:
    # @dev returns if the address supplied is the owner or admin address
    # @param _addr is the address in query
    # @return bool indicating status
    return _sender == self.owner or _sender == self.admin

@view
@internal
def _is_eoa(_sender: address, _origin: address) -> bool:
    # @dev returns if the sender is equal to the origin (ie, is EOA)
    # @param _sender is the message caller address
    # @param _origin is the tx origin
    # @return bool indicating if sender is origin
    return _sender == _origin

@pure
@internal
def _verify_proof(_root: bytes32, _leaf: bytes32, _proof: bytes32[100]) -> bool:
    # @dev verifies sorted merkle proof against the supplied hash
    computed_hash: bytes32 = _leaf
    for proof in _proof:
        if convert(computed_hash, uint256) < convert(proof, uint256):
            computed_hash = keccak256(concat(computed_hash, proof))
        else:
            computed_hash = keccak256(concat(proof, computed_hash))
    return computed_hash == _root

@external
def open_presale():
    # @dev sets presale open and public sale closed
    # @dev requires admin or owner for msg.sender
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    self.is_presale_open = True
    self.is_public_sale_open = False

@external
def open_public_sale():
    # @dev sets public sale open and closes presale
    # @dev requires admin or owner for msg.sender
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    self.is_public_sale_open = True
    self.is_presale_open = False

@external
def close_sales():
    # @dev closes presale and public sale
    # @dev requires admin or owner for msg.sender
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    self.is_public_sale_open = False
    self.is_presale_open = False

@external
def set_mint_allowance(_allowance: uint256):
    # @dev sets mint allowance
    # @dev requires admin or owner for msg.sender
    # @param _allowance is the new mint allowance
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    self.mint_allowance = _allowance

@external
def set_base_uri(_uri: String[100]):
    # @dev function to set new base uri for metadata
    # @dev requires admin or owner for msg.sender
    # @param _uri is the new base uri
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    self.base_uri = _uri

@external
def set_royalty_info(_recipient: address, _perc: uint256):
    # @dev function to set new royalty information
    # @dev requires admin or owner for msg.snder
    # @param _recipient is the new royalty recipient
    # @param _perc is the new royalty percentage
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    self.royalty_addr = _recipient
    self.royalty_perc = _perc

@external
def set_admin_address(_admin: address):
    # @dev function to set a new admin address
    # @dev requires msg.sender to be the owner
    # @param _admin is the new admin address
    # Throws if _admin is the zero address
    assert _admin != ZERO_ADDRESS, "Admin cannot be the zero address"
    assert msg.sender == self.owner, "Only owner can call this function"
    self.admin = _admin

@external
def set_payout_address(_payout: address):
    # @dev function to set a new payout address
    # @dev requires msg.sender to be the owner
    # @param _payout is the new payout address
    # Throws if _payout is the zero address
    assert _payout != ZERO_ADDRESS, "Payout cannot be the zero address"
    assert msg.sender == self.owner, "Only owner can call this function"
    self.payout = _payout

@external
def set_owner_address(_owner: address):
    # @dev function to set a new owner address
    # @dev requires msg.sender to be the owner
    # @param _owner is the new owner address
    # Throws if _admin is the zero address
    # CAUTION: THIS WILL SET THE CONTRACT OWNERSHIP TO A NEW ADDRESS
    assert _owner != ZERO_ADDRESS, "Owner cannot be the zero address"
    assert msg.sender == self.owner, "Only owner can call this function"
    self.owner = _owner

@external
def withdraw_ether():
    # @dev function to withdraw contract balance
    # @dev requires admin or owner
    # @dev sends to payout address
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    send(self.payout, self.balance)

@external
def withdraw_erc20(_token_addr: address) -> bool:
    # @dev function to withdraw contract balance of an ERC20 token
    # @dev requires admin or owner
    # @dev sends to payout address
    # @return bool indicating success
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    token: ERC20 = ERC20(_token_addr)
    token_balance: uint256 = token.balanceOf(self)
    success: bool = token.transfer(self.payout, token_balance)
    return success

@external
def owner_mint(_num: DynArray[uint8, 200]):
    # @dev function to mint a specified number to the owner address
    # @dev requires admin or owner
    # @param _num is a dyanmic array whose length determines how many to mint
    # @dev all values in this can be 0
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    assert self.counter + len(_num) <= self.totalSupply, "No tokens left to mint"
    c: uint256 = self.counter
    self.counter += len(_num)
    for i in _num:
        c += 1
        self._mint(self.owner, c)

@external
def airdrop(_addr: DynArray[address, 200]):
    # @dev function to airdrop to addresses
    # @dev requires admin or owner
    # @param _addr is the list of addresses
    assert self._is_admin_or_owner(msg.sender), "Caller is not admin or owner"
    assert self.counter + len(_addr) <= self.totalSupply, "No tokens left to mint"
    c: uint256 = self.counter
    self.counter += len(_addr)
    for addr in _addr:
        c += 1
        self._mint(addr, c)

@payable
@external
def mint(_proof: bytes32[100]):
    # @dev mint function exposed
    # @dev must be an EOA
    # @dev can only mint once per call
    # @dev makes use of _mint function as callers are EOAs
    assert self._is_eoa(msg.sender, tx.origin), "Caller must be an EOA"
    assert self.counter < self.totalSupply, "No tokens left to mint"
    assert msg.value >= self.mint_price, "Not enough ether sent"
    assert self.num_minted[msg.sender] < self.mint_allowance, "Caller has already minted"
    if self.is_presale_open:
        leaf: bytes32 = keccak256(_abi_encode(msg.sender))
        assert self._verify_proof(merkle_root, leaf, _proof), "Not on the allowlist"
    elif not self.is_public_sale_open:
        raise "Minting not open"

    self.num_minted[msg.sender] += 1
    self.counter += 1
    self._mint(msg.sender, self.counter)

@view
@external
def get_remaining_supply() -> uint256:
    # @return returns the remaining supply available for mint
    return self.totalSupply - self.counter

@view
@external
def get_num_minted(_addr: address) -> uint256:
    # @return number minted by address
    return self.num_minted[_addr]