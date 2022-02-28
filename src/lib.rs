#![no_std]

extern crate alloc;

const NFT_AMOUNT: u32 = 1;
const ROYALTIES_MAX: u32 = 10_000;
// This is the most popular gateway, but it doesn't matter the most important is IPFS CID
const IPFS_GATEWAY_HOST: &[u8] = "https://ipfs.io/ipfs/".as_bytes();
const METADATA_KEY_NAME: &[u8] = "metadata:".as_bytes();
const METADATA_FILE_EXTENSION: &[u8] = ".json".as_bytes();
const ATTR_SEPARATOR: &[u8] = ";".as_bytes();
const URI_SLASH: &[u8] = "/".as_bytes();
const TAGS_KEY_NAME: &[u8] = "tags:".as_bytes();
const DEFAULT_IMG_FILE_EXTENSION: &[u8] = ".png".as_bytes();
const DEFAULT_IMG_FILENAME: &[u8] = "1".as_bytes();
const DEFAULT_TOKEN_SUFFIX: &[u8] = "1".as_bytes();

elrond_wasm::imports!();
elrond_wasm::derive_imports!();

#[elrond_wasm::contract]
pub trait ElvenTools {
    #[init]
    fn init(
        &self,
        image_base_cid: ManagedBuffer,
        metadata_base_cid: ManagedBuffer,
        amount_of_tokens: u32,
        tokens_limit_per_address: u32,
        royalties: BigUint,
        selling_price: BigUint,
        #[var_args] file_extension: OptionalArg<ManagedBuffer>,
        #[var_args] filename: OptionalArg<ManagedBuffer>,
        #[var_args] token_name_suffix: OptionalArg<ManagedBuffer>,
        #[var_args] tags: OptionalArg<ManagedBuffer>,
        #[var_args] provenance_hash: OptionalArg<ManagedBuffer>,
        #[var_args] is_metadata_in_uris: OptionalArg<bool>,
    ) -> SCResult<()> {
        require!(royalties <= ROYALTIES_MAX, "Royalties cannot exceed 100%!");
        require!(
            amount_of_tokens >= 1,
            "Amount of tokens to mint should be at least 1!"
        );
        require!(
            tokens_limit_per_address >= 1,
            "Tokens limit per address should be at least 1!"
        );

        self.image_base_cid().set_if_empty(&image_base_cid);
        self.metadata_base_cid().set_if_empty(&metadata_base_cid);
        self.amount_of_tokens_total()
            .set_if_empty(&amount_of_tokens);
        self.tokens_limit_per_address_total()
            .set_if_empty(&tokens_limit_per_address);
        self.provenance_hash()
            .set_if_empty(&provenance_hash.into_option().unwrap_or_default());
        self.royalties().set_if_empty(&royalties);
        self.selling_price().set_if_empty(&selling_price);
        self.tags()
            .set_if_empty(&tags.into_option().unwrap_or_default());
        self.file_extension().set_if_empty(
            &file_extension
                .into_option()
                .unwrap_or_else(|| ManagedBuffer::new_from_bytes(DEFAULT_IMG_FILE_EXTENSION)),
        );
        self.filename().set_if_empty(
            &filename
                .into_option()
                .unwrap_or_else(|| ManagedBuffer::new_from_bytes(DEFAULT_IMG_FILENAME)),
        );
        self.token_name_suffix().set_if_empty(
            &token_name_suffix
                .into_option()
                .unwrap_or_else(|| ManagedBuffer::new_from_bytes(DEFAULT_TOKEN_SUFFIX)),
        );
        self.is_metadata_in_uris()
            .set_if_empty(&is_metadata_in_uris.into_option().unwrap_or_default());

        let paused = true;
        self.paused().set_if_empty(&paused);

        Ok(())
    }

    // Issue main collection token/handler
    #[only_owner]
    #[payable("EGLD")]
    #[endpoint(issueToken)]
    fn issue_token(
        &self,
        #[payment] issue_cost: BigUint,
        token_name: ManagedBuffer,
        token_ticker: ManagedBuffer,
    ) -> SCResult<AsyncCall> {
        require!(self.nft_token_id().is_empty(), "Token already issued!");

        self.nft_token_name().set(&token_name);

        Ok(self
            .send()
            .esdt_system_sc_proxy()
            .issue_non_fungible(
                issue_cost,
                &token_name,
                &token_ticker,
                NonFungibleTokenProperties {
                    can_freeze: false,
                    can_wipe: false,
                    can_pause: false,
                    can_change_owner: false,
                    can_upgrade: false,
                    can_add_special_roles: true,
                },
            )
            .async_call()
            .with_callback(self.callbacks().issue_callback()))
    }

    #[only_owner]
    #[endpoint(setLocalRoles)]
    fn set_local_roles(&self) -> SCResult<AsyncCall> {
        require!(!self.nft_token_id().is_empty(), "Token not issued!");

        Ok(self
            .send()
            .esdt_system_sc_proxy()
            .set_special_roles(
                &self.blockchain().get_sc_address(),
                &self.nft_token_id().get(),
                (&[EsdtLocalRole::NftCreate][..]).into_iter().cloned(),
            )
            .async_call())
    }

    #[only_owner]
    #[endpoint(pauseMinting)]
    fn pause_minting(&self) -> SCResult<()> {
        let paused = true;
        self.paused().set(&paused);

        Ok(())
    }

    #[only_owner]
    #[endpoint(startMinting)]
    fn start_minting(&self) -> SCResult<()> {
        require!(!self.nft_token_id().is_empty(), "Token not issued!");

        self.paused().clear();

        Ok(())
    }

    // The owner can change CIDs only before any NFT is minted!
    #[only_owner]
    #[endpoint(changeBaseCids)]
    fn change_base_cids(
        &self,
        image_base_cid: ManagedBuffer,
        metadata_base_cid: ManagedBuffer,
    ) -> SCResult<()> {
        require!(
            self.minted_indexes_total().is_empty(),
            "You can't change the CIDs. There are some tokens minted already!"
        );

        self.image_base_cid().set(&image_base_cid);
        self.metadata_base_cid().set(&metadata_base_cid);

        Ok(())
    }

    #[only_owner]
    #[endpoint(setNewTokensLimitPerAddress)]
    fn set_new_tokens_limit_per_address(&self, limit: u32) -> SCResult<()> {
        self.tokens_limit_per_address_total().set(limit);
        Ok(())
    }

    #[only_owner]
    #[endpoint(setFilename)]
    fn set_filename(&self, filename: ManagedBuffer, file_extension: ManagedBuffer, token_name_suffix: ManagedBuffer) -> SCResult<()> {
        self.filename().set(filename);
        self.file_extension().set(file_extension);
        self.token_name_suffix().set(token_name_suffix);
        Ok(())
    }

    // As an owner of the smart contract, you can send randomly minted NFTs to chosen addresses.
    #[only_owner]
    #[endpoint(giveaway)]
    fn giveaway(&self, address: ManagedAddress, amount_of_tokens: u32) -> SCResult<()> {
        require!(!self.nft_token_id().is_empty(), "Token not issued!");

        require!(
            self.initial_shuffle_triggered().get(),
            "Run the shuffle mechanism at least once!"
        );

        let token = self.nft_token_id().get();
        let roles = self.blockchain().get_esdt_local_roles(&token);

        require!(
            roles.has_role(&EsdtLocalRole::NftCreate),
            "NFTCreate role not set!"
        );

        require!(
            self.get_current_left_tokens_amount() >= amount_of_tokens,
            "All tokens have been minted already or the amount you want to mint is too much. Check limits! (totally or per drop)!"
        );

        for _ in 0..amount_of_tokens {
            self.mint_single_nft(BigUint::zero(), OptionalArg::Some(address.clone()))
                .unwrap();
        }

        Ok(())
    }

    // As an owner, claim Smart Contract balance - temporary solution for royalities, the SC has to be payable to be able to get royalties
    #[only_owner]
    #[endpoint(claimScFunds)]
    fn claim_sc_funds(&self) -> SCResult<()> {
        self.send().direct_egld(
            &self.blockchain().get_caller(),
            &self
                .blockchain()
                .get_sc_balance(&TokenIdentifier::egld(), 0),
            &[],
        );

        Ok(())
    }

    #[only_owner]
    #[endpoint(populateIndexes)]
    fn populate_indexes(&self, amount: u32) -> SCResult<()> {
        let initial_indexes_populate_done = self.initial_indexes_populate_done();

        require!(
            !initial_indexes_populate_done.get(),
            "The indexes are already properly populated!"
        );

        let amount_of_tokens = self.amount_of_tokens_total().get();
        let mut v_mapper = self.tokens_left_to_mint();
        let v_mapper_len = v_mapper.len() as u32;
        let total_amount = v_mapper_len + amount;

        require!(
            amount > 0 && total_amount <= amount_of_tokens,
            "Wrong amount of tokens!"
        );

        let from = v_mapper_len + 1;
        let to = from + amount - 1;
        for i in from..=to {
            v_mapper.push(&i);
        }

        if amount_of_tokens == total_amount {
            self.initial_indexes_populate_done().set(true);
        }

        Ok(())
    }
    // Private single token mint function. It is also used for the giveaway.
    fn mint_single_nft(
        &self,
        payment_amount: BigUint,
        #[var_args] giveaway_address: OptionalArg<ManagedAddress>,
    ) -> SCResult<()> {
        let next_index_to_mint_tuple = self.next_index_to_mint().get();

        let amount = &BigUint::from(NFT_AMOUNT);

        let token = self.nft_token_id().get();
        let token_name = self.build_token_name_buffer();

        let royalties = self.royalties().get();

        let attributes = self.build_attributes_buffer();

        let attributes_hash = self
            .crypto()
            .sha256_legacy(&attributes.to_boxed_bytes().as_slice());
        let hash_buffer = ManagedBuffer::from(attributes_hash.as_bytes());

        let uris = self.build_uris_vec();

        let nonce = self.send().esdt_nft_create(
            &token,
            &amount,
            &token_name,
            &royalties,
            &hash_buffer,
            &attributes,
            &uris,
        );

        let giveaway_address = giveaway_address
            .into_option()
            .unwrap_or_else(|| ManagedAddress::zero());

        let caller = self.blockchain().get_caller();

        let receiver;

        if giveaway_address.is_zero() {
            receiver = &caller;
        } else {
            receiver = &giveaway_address;
        }

        self.send()
            .direct(&receiver, &token, nonce, &BigUint::from(NFT_AMOUNT), &[]);

        if payment_amount > 0 {
            self.minted_per_address_total(&caller)
                .update(|sum| *sum += 1);

            if !self.opened_drop().is_empty() {
                let opened_drop_id = self.opened_drop().get();
                let existing_address_value = self
                    .minted_per_address_per_drop(opened_drop_id)
                    .get(&caller)
                    .unwrap_or_default();
                if existing_address_value > 0 {
                    let next_value = existing_address_value + 1;
                    self.minted_per_address_per_drop(opened_drop_id)
                        .insert(caller, next_value);
                } else {
                    self.minted_per_address_per_drop(opened_drop_id)
                        .insert(caller, 1);
                }
            }

            let payment_nonce: u64 = 0;
            let payment_token = &TokenIdentifier::egld();

            let owner = self.blockchain().get_owner_address();
            self.send()
                .direct(&owner, &payment_token, payment_nonce, &payment_amount, &[]);
        }

        // Choose next index to mint here from shuffled Vec
        self.handle_next_index_setup(next_index_to_mint_tuple);

        Ok(())
    }

    #[endpoint(shuffle)]
    fn shuffle(&self) -> SCResult<()> {
        require!(!self.nft_token_id().is_empty(), "Token not issued!");
        let v_mapper = self.tokens_left_to_mint();
        require!(
            !v_mapper.is_empty(),
            "There is nothing to shuffle. Indexes not populated or there are no tokens to mint left!"
        );

        let initial_shuffle_triggered = self.initial_shuffle_triggered().get();

        if !initial_shuffle_triggered {
            self.initial_shuffle_triggered().set(true);
        }

        self.do_shuffle();

        Ok(())
    }

    fn do_shuffle(&self) {
        let vec = self.tokens_left_to_mint();

        let vec_len = vec.len();
        let mut rand_source = RandomnessSource::<Self::Api>::new();

        let index = rand_source.next_usize_in_range(1, vec_len + 1);

        let choosen_item = vec.get(index);

        self.next_index_to_mint().set((index, choosen_item));
    }

    #[callback]
    fn issue_callback(&self, #[call_result] result: ManagedAsyncCallResult<TokenIdentifier>) {
        match result {
            ManagedAsyncCallResult::Ok(token_id) => {
                self.nft_token_id().set(&token_id);
            }
            ManagedAsyncCallResult::Err(_) => {
                let caller = self.blockchain().get_owner_address();
                let (returned_tokens, token_id) = self.call_value().payment_token_pair();
                if token_id.is_egld() && returned_tokens > 0 {
                    self.send()
                        .direct(&caller, &token_id, 0, &returned_tokens, &[]);
                }
            }
        }
    }


    fn handle_next_index_setup(&self, minted_index_tuple: (usize, u32)) {
        let is_minted_indexes_total_empty = self.minted_indexes_total().is_empty();
        if is_minted_indexes_total_empty {
            self.minted_indexes_total().set(1);
        } else {
            self.minted_indexes_total().update(|sum| *sum += 1);
        }

        let drop_amount = self.amount_of_tokens_per_drop().get();
        if drop_amount > 0 {
            let is_minted_indexes_by_drop_empty = self.minted_indexes_by_drop().is_empty();
            if is_minted_indexes_by_drop_empty {
                self.minted_indexes_by_drop().set(1);
            } else {
                self.minted_indexes_by_drop().update(|sum| *sum += 1);
            }
        }

        let total_tokens_left = self.total_tokens_left().ok().unwrap_or_default();

        if total_tokens_left > 0 {
            let mut vec = self.tokens_left_to_mint();
            vec.swap_remove(minted_index_tuple.0);
            self.do_shuffle();
        }
    }

    fn build_uris_vec(&self) -> ManagedVec<ManagedBuffer> {
        use alloc::string::ToString;

        let is_metadata_in_uris = self.is_metadata_in_uris().get();

        let mut uris = ManagedVec::new();

        let image_cid = self.image_base_cid().get();
        let metadata_cid = self.metadata_base_cid().get();
        let uri_slash = ManagedBuffer::new_from_bytes(URI_SLASH);
        let metadata_file_extension = ManagedBuffer::new_from_bytes(METADATA_FILE_EXTENSION);
        let image_file_extension = self.file_extension().get();
        let file_name = self.filename().get();

        let mut img_ipfs_gateway_uri = ManagedBuffer::new_from_bytes(IPFS_GATEWAY_HOST);
        img_ipfs_gateway_uri.append(&image_cid);
        img_ipfs_gateway_uri.append(&uri_slash);
        img_ipfs_gateway_uri.append(&file_name);
        img_ipfs_gateway_uri.append(&image_file_extension);

        uris.push(img_ipfs_gateway_uri);

        if is_metadata_in_uris {
            let mut ipfs_metadata_uri = ManagedBuffer::new_from_bytes(IPFS_GATEWAY_HOST);
            ipfs_metadata_uri.append(&metadata_cid);
            ipfs_metadata_uri.append(&uri_slash);
            ipfs_metadata_uri.append(&file_name);
            ipfs_metadata_uri.append(&metadata_file_extension);

            uris.push(ipfs_metadata_uri);
        }

        uris
    }

    // This can be probably optimized with attributes struct, had problems with decoding on the api side
    fn build_attributes_buffer(&self) -> ManagedBuffer {
        use alloc::string::ToString;

        let metadata_key_name = ManagedBuffer::new_from_bytes(METADATA_KEY_NAME);
        let metadata_filename = self.filename().get();
        let metadata_file_extension = ManagedBuffer::new_from_bytes(METADATA_FILE_EXTENSION);
        let metadata_cid = self.metadata_base_cid().get();
        let separator = ManagedBuffer::new_from_bytes(ATTR_SEPARATOR);
        let metadata_slash = ManagedBuffer::new_from_bytes(URI_SLASH);
        let tags_key_name = ManagedBuffer::new_from_bytes(TAGS_KEY_NAME);

        let mut attributes = ManagedBuffer::new();
        attributes.append(&tags_key_name);
        attributes.append(&self.tags().get());
        attributes.append(&separator);
        attributes.append(&metadata_key_name);
        attributes.append(&metadata_cid);
        attributes.append(&metadata_slash);
        attributes.append(&metadata_filename);
        attributes.append(&metadata_file_extension);

        attributes
    }

    fn build_token_name_buffer(&self) -> ManagedBuffer {
        use alloc::string::ToString;

        let mut full_token_name = ManagedBuffer::new();
        let token_name_suffix = self.token_name_suffix().get();
        let token_prefix = ManagedBuffer::new_from_bytes("Faceless Allies - ".as_bytes());

        full_token_name.append(&token_prefix);
        full_token_name.append(&token_name_suffix);

        full_token_name
    }

    fn get_current_left_tokens_amount(&self) -> u32 {
        let drop_amount = self.amount_of_tokens_per_drop().get();
        let tokens_left;
        let paused = true;
        if drop_amount > 0 {
            tokens_left = self.drop_tokens_left().ok().unwrap_or_default();
        } else {
            tokens_left = self.total_tokens_left().ok().unwrap_or_default();
        }

        if tokens_left == 0 {
            self.paused().set(&paused);
        }

        tokens_left
    }

    #[view(getDropTokensLeft)]
    fn drop_tokens_left(&self) -> SCResult<u32> {
        let minted_tokens = self.minted_indexes_by_drop().get();
        let amount_of_tokens = self.amount_of_tokens_per_drop().get();
        let left_tokens: u32 = amount_of_tokens - minted_tokens as u32;

        Ok(left_tokens)
    }

    #[view(getTotalTokensLeft)]
    fn total_tokens_left(&self) -> SCResult<u32> {
        let minted_tokens = self.minted_indexes_total().get();
        let amount_of_tokens = self.amount_of_tokens_total().get();
        let left_tokens: u32 = amount_of_tokens - minted_tokens as u32;

        Ok(left_tokens)
    }

    #[view(getMintedPerAddressPerDrop)]
    fn get_minted_per_address_per_drop(&self, address: ManagedAddress) -> SCResult<u32> {
        let minted_per_address_per_drop: u32;
        if !self.opened_drop().is_empty() {
            let opened_drop_id = self.opened_drop().get();
            minted_per_address_per_drop = self
                .minted_per_address_per_drop(opened_drop_id)
                .get(&address)
                .unwrap_or_default();
        } else {
            minted_per_address_per_drop = 0;
        }

        Ok(minted_per_address_per_drop)
    }

    #[view(getAllowlistAddressCheck)]
    fn allowlist_address_check(&self, address: ManagedAddress) -> SCResult<bool> {
        Ok(self.allowlist().contains(&address))
    }

    #[view(getAllowlistSize)]
    fn allowlist_size(&self) -> SCResult<usize> {
        Ok(self.allowlist().len())
    }

    #[view(getNftTokenId)]
    #[storage_mapper("nftTokenId")]
    fn nft_token_id(&self) -> SingleValueMapper<TokenIdentifier>;

    #[view(getNftTokenName)]
    #[storage_mapper("nftTokenName")]
    fn nft_token_name(&self) -> SingleValueMapper<ManagedBuffer>;

    #[view(getNftPrice)]
    #[storage_mapper("nftPrice")]
    fn selling_price(&self) -> SingleValueMapper<BigUint>;

    #[view(getProvenanceHash)]
    #[storage_mapper("provenanceHash")]
    fn provenance_hash(&self) -> SingleValueMapper<ManagedBuffer>;

    #[view(getTokensLimitPerAddressTotal)]
    #[storage_mapper("tokensLimitPerAddressTotal")]
    fn tokens_limit_per_address_total(&self) -> SingleValueMapper<u32>;

    #[view(getMintedPerAddressTotal)]
    #[storage_mapper("mintedPerAddressTotal")]
    fn minted_per_address_total(&self, address: &ManagedAddress) -> SingleValueMapper<u32>;

    #[view(getTokensLimitPerAddressPerDrop)]
    #[storage_mapper("tokensLimitPerAddressPerDrop")]
    fn tokens_limit_per_address_per_drop(&self) -> SingleValueMapper<u32>;

    #[view(isAllowlistEnabled)]
    #[storage_mapper("isAllowlistEnabled")]
    fn is_allowlist_enabled(&self) -> SingleValueMapper<bool>;

    #[storage_mapper("allowlist")]
    fn allowlist(&self) -> SetMapper<ManagedAddress>;

    #[storage_mapper("mintedPerAddressPerDrop")]
    fn minted_per_address_per_drop(&self, id: u16) -> MapMapper<ManagedAddress, u32>;

    #[storage_mapper("openedDrop")]
    fn opened_drop(&self) -> SingleValueMapper<u16>;

    #[storage_mapper("iamgeBaseCid")]
    fn image_base_cid(&self) -> SingleValueMapper<ManagedBuffer>;

    #[storage_mapper("metadaBaseCid")]
    fn metadata_base_cid(&self) -> SingleValueMapper<ManagedBuffer>;

    #[view(getFileExtension)]
    #[storage_mapper("fileExtension")]
    fn file_extension(&self) -> SingleValueMapper<ManagedBuffer>;
    
    #[view(getFilename)]
    #[storage_mapper("filename")]
    fn filename(&self) -> SingleValueMapper<ManagedBuffer>;
    
    #[view(getTokenNameSuffix)]
    #[storage_mapper("token_name_suffix")]
    fn token_name_suffix(&self) -> SingleValueMapper<ManagedBuffer>;

    #[storage_mapper("amountOfTokensTotal")]
    fn amount_of_tokens_total(&self) -> SingleValueMapper<u32>;

    #[storage_mapper("mintedIndexesTotal")]
    fn minted_indexes_total(&self) -> SingleValueMapper<u32>;

    #[storage_mapper("mintedIndexesByDrop")]
    fn minted_indexes_by_drop(&self) -> SingleValueMapper<u32>;

    #[storage_mapper("royalties")]
    fn royalties(&self) -> SingleValueMapper<BigUint>;

    #[storage_mapper("paused")]
    fn paused(&self) -> SingleValueMapper<bool>;

    #[storage_mapper("tags")]
    fn tags(&self) -> SingleValueMapper<ManagedBuffer>;

    #[storage_mapper("amountOfTokensPerDrop")]
    fn amount_of_tokens_per_drop(&self) -> SingleValueMapper<u32>;

    #[storage_mapper("nextIndexToMint")]
    fn next_index_to_mint(&self) -> SingleValueMapper<(usize, u32)>;

    #[storage_mapper("tokensLeftToMint")]
    fn tokens_left_to_mint(&self) -> VecMapper<u32>;

    #[storage_mapper("initialShuffleTriggered")]
    fn initial_shuffle_triggered(&self) -> SingleValueMapper<bool>;

    #[storage_mapper("initialIndexesPopulateDone")]
    fn initial_indexes_populate_done(&self) -> SingleValueMapper<bool>;

    #[storage_mapper("isMetadataInUris")]
    fn is_metadata_in_uris(&self) -> SingleValueMapper<bool>;
}
