use bdk::blockchain::ElectrumBlockchain;
use bdk::database::MemoryDatabase;
use bdk::bitcoin::Network;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, KeySource};
// use bdk::bitcoin::Amount;
use bdk::electrum_client::Client;
// use bdk::bitcoincore_rpc::{Auth as rpc_auth, Client, RpcApi};
// use bdk::wallet::wallet_name_from_descriptor;
use bdk::blockchain::noop_progress;
// use bdk::blockchain::rpc::{Auth, RpcBlockchain, RpcConfig};
// use bdk::blockchain::{ConfigurableBlockchain, NoopProgress};

use bdk::keys::bip39::{Mnemonic, Language, WordCount};
use bdk::keys::{GeneratedKey, GeneratableKey, ExtendedKey, DerivableKey, DescriptorKey};
use bdk::keys::DescriptorKey::Secret;

use bdk::miniscript::miniscript::Segwitv0;

use bdk::Wallet;
// use bdk::wallet::{AddressIndex, signer::SignOptions};

// use bdk::sled;

use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
        let phrase = "slight order consider pencil belt air purchase hawk payment hurry heart half";
        let mnemonic = Mnemonic::parse_in(Language::English,phrase).unwrap();
        let password = Some("walletpassword".to_string());

        let (receive_desc, change_desc) = get_descriptors_fr_menmonic_pwd(mnemonic, password);
        println!("recv: {:#?}, \nchng: {:#?}", receive_desc, change_desc);

        // Use deterministic wallet name derived from descriptor
        let external_descriptor =  receive_desc.as_str();
        let internal_descriptor = change_desc.as_str();
      
        // let wallet_name = wallet_name_from_descriptor(
        //     external_descriptor,
        //     Some(internal_descriptor),
        //     Network::Testnet,
        //     &Secp256k1::new()
        // ).unwrap();
        // println!("wallet name: {:#?}", wallet_name);

        let wallet: Wallet<ElectrumBlockchain, MemoryDatabase> = Wallet::new(
            external_descriptor,
            Some(internal_descriptor),
            Network::Testnet,
            MemoryDatabase::new(),
            ElectrumBlockchain::from(Client::new("ssl://electrum.blockstream.info:60002").unwrap()),
        )?;    

        // let address = wallet.get_address(AddressIndex::New)?;
        // println!("Generated Address: {}", address);
    
        wallet.sync(noop_progress(), None)?;
    
        let balance = wallet.get_balance()?;
        println!("Wallet balance in SAT: {}", balance);
    

        Ok(()) 
    }

// generate fresh descriptor strings and return them via (receive, change) tupple 
fn get_descriptors() -> (String, String) {
    // Create a new secp context
    let secp = Secp256k1::new();

    // You can also set a password to unlock the mnemonic
    let password = Some("beerbravebullgin".to_string());

    // Generate a fresh menmonic, and from their, a fresh private key xprv
    let mnemonic: GeneratedKey<_, Segwitv0> =
                Mnemonic::generate((WordCount::Words12, Language::English)).unwrap();
    let mnemonic = mnemonic.into_key();
    println!("Mnemonic:{:#?}",mnemonic);
 
    let xkey: ExtendedKey = (mnemonic, password).into_extended_key().unwrap();
    let xprv = xkey.into_xprv(Network::Testnet).unwrap();

    // Derive our dewscriptors to use
    // We use the following paths for recieve and change descriptor
    // recieve: "m/84h/1h/0h/0"
    // change: "m/84h/1h/0h/1" 
    let mut keys = Vec::new();

    for path in ["m/84h/1h/0h/0", "m/84h/1h/0h/1"] {
        let deriv_path: DerivationPath = DerivationPath::from_str(path).unwrap();
        let derived_xprv = &xprv.derive_priv(&secp, &deriv_path).unwrap();

        let origin: KeySource = (xprv.fingerprint(&secp), deriv_path);
        let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
        derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default()).unwrap();

        // Wrap the derived key with the wpkh() string to produce a descriptor string
        if let Secret(key, _, _) = derived_xprv_desc_key {
            let mut desc = "wpkh(".to_string();
            desc.push_str(&key.to_string());
            desc.push_str(")");
            keys.push(desc);
        }
    }
    
    // Return the keys as a tupple
    (keys[0].clone(), keys[1].clone())
}

fn get_descriptors_fr_menmonic_pwd(mnemonic: Mnemonic, password: Option<String>) -> (String, String) {
    // Create a new secp context
    let secp = Secp256k1::new();

    let xkey: ExtendedKey = (mnemonic, password).into_extended_key().unwrap();
    let xprv = xkey.into_xprv(Network::Testnet).unwrap();

    // Derive our dewscriptors to use
    // We use the following paths for recieve and change descriptor
    // recieve: "m/84h/1h/0h/0"
    // change: "m/84h/1h/0h/1" 
    let mut keys = Vec::new();

    for path in ["m/84h/1h/0h/0", "m/84h/1h/0h/1"] {
        let deriv_path: DerivationPath = DerivationPath::from_str(path).unwrap();
        let derived_xprv = &xprv.derive_priv(&secp, &deriv_path).unwrap();
        let origin: KeySource = (xprv.fingerprint(&secp), deriv_path);
        let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
        derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default()).unwrap();

        // Wrap the derived key with the wpkh() string to produce a descriptor string
        if let Secret(key, _, _) = derived_xprv_desc_key {
            let mut desc = "wpkh(".to_string();
            desc.push_str(&key.to_string());
            desc.push_str(")");
            keys.push(desc);
        }
    }
    
    // Return the keys as a tupple
    (keys[0].clone(), keys[1].clone())
}
