// AUTO-GENERATED from RFC 9382 Appendix B (ciphersuite P256-SHA256-HKDF-HMAC).
// Source: https://www.rfc-editor.org/rfc/rfc9382 — do not edit hex values by hand.

use sha2::{Digest, Sha256};
use syncbond_core::pairing_spake2::{
    scalar_from_hex, Spake2Initiator, Spake2Responder, TestScalars,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Vector {
    id_a: &'static str,
    id_b: &'static str,
    w: &'static str,
    x: &'static str,
    y: &'static str,
    p_a: &'static str,
    p_b: &'static str,
    tt: &'static str,
    hash_tt: &'static str,
    ke: &'static str,
    ka: &'static str,
    kc_a: &'static str,
    kc_b: &'static str,
    conf_a: &'static str,
    conf_b: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        id_a: "server",
        id_b: "client",
        w: "2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f",
        x: "43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729",
        y: "dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be",
        p_a: concat!(
            "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470",
            "f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f91",
            "2c"
        ),
        p_b: concat!(
            "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676",
            "d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0",
            "b7"
        ),
        tt: concat!(
            "06000000000000007365727665720600000000000000636c69656e7441000000",
            "0000000004a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a87984",
            "34751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb411698",
            "8ede5f912c41000000000000000406557e482bd03097ad0cbaa5df82115460d9",
            "51e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a115",
            "5cf8f1543ceca528afb591a1e0b741000000000000000412af7e897178506719",
            "13e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2",
            "fa6a406d528501f907e04d97515fbe83db277b715d332520000000000000002e",
            "e57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f"
        ),
        hash_tt: "0e0672dc86f8e45565d338b0540abe6915bdf72e2b35b5c9e5663168e960a91b",
        ke: "0e0672dc86f8e45565d338b0540abe69",
        ka: "15bdf72e2b35b5c9e5663168e960a91b",
        kc_a: "00c12546835755c86d8c0db7851ae86f",
        kc_b: "a9fa3406c3b781b93d804485430ca27a",
        conf_a: "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0",
        conf_b: "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b",
    },
    Vector {
        id_a: "",
        id_b: "client",
        w: "0548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae",
        x: "403abbe3b1b4b9ba17e3032849759d723939a27a27b9d921c500edde18ed654b",
        y: "903023b6598908936ea7c929bd761af6039577a9c3f9581064187c3049d87065",
        p_a: concat!(
            "04a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f",
            "44fb92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e91",
            "8a"
        ),
        p_b: concat!(
            "04e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a6",
            "1b881a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7",
            "fc"
        ),
        tt: concat!(
            "00000000000000000600000000000000636c69656e74410000000000000004a8",
            "97b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f44fb",
            "92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a41",
            "0000000000000004e0f816fd1c35e22065d5556215c097e799390d16661c386e",
            "0ecc84593974a61b881a8c82327687d0501862970c64565560cb5671f6960480",
            "50ca66ca5f8cc7fc4100000000000000048f83ec9f6e4f87cc6f9dc740bdc276",
            "9725f923364f01c84148c049a39a735ebda82eac03e00112fd6a5710682767cf",
            "f5361f7e819e53d8d3c3a2922e0d837aa620000000000000000548d8729f7305",
            "89e579b0475a582c1608138ddf7054b73b5381c7e883e2efae"
        ),
        hash_tt: "642f05c473c2cd79909f9a841e2f30a70bf89b18180af97353ba198789c2b963",
        ke: "642f05c473c2cd79909f9a841e2f30a7",
        ka: "0bf89b18180af97353ba198789c2b963",
        kc_a: "c6be376fc7cd1301fd0a13adf3e7bffd",
        kc_b: "b7243f4ae60440a49b3f8cab3c1fba07",
        conf_a: "47d29e6666af1b7dd450d571233085d7a9866e4d49d2645e2df975489521232b",
        conf_b: "3313c5cefc361d27fb16847a91c2a73b766ffa90a4839122a9b70a2f6bd1d6df",
    },
    Vector {
        id_a: "server",
        id_b: "",
        w: "626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254",
        x: "07adb3db6bc623d3399726bfdbfd3d15a58ea776ab8a308b00392621291f9633",
        y: "b6a4fc8dbb629d4ba51d6f91ed1532cf87adec98f25dd153a75accafafedec16",
        p_a: concat!(
            "04f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2",
            "e15a873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763",
            "b0"
        ),
        p_b: concat!(
            "040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101",
            "e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34",
            "db"
        ),
        tt: concat!(
            "06000000000000007365727665720000000000000000410000000000000004f8",
            "8fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2e15a",
            "873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b041",
            "00000000000000040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4",
            "bdfd353f031101e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39b",
            "a0f31a9661bd34db41000000000000000445ee233b8ecb51ebd6e7da3f307e88",
            "a1616bae2166121221fdc0dadb986afaf3ec8a988dc9c626fa3b99f58a7ca7c9",
            "b844bb3e8dd9554aafc5b53813504c1cbe2000000000000000626e0cdc7b14c9",
            "db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254"
        ),
        hash_tt: "005184ff460da2ce59062c87733c299c3521297d736598fc0a1127600efa1afb",
        ke: "005184ff460da2ce59062c87733c299c",
        ka: "3521297d736598fc0a1127600efa1afb",
        kc_a: "f3da53604f0aeecea5a33be7bddf6edf",
        kc_b: "9e3f86848736f159bd92b6e107ec6799",
        conf_a: "bc9f9bbe99f26d0b2260e6456e05a86196a3307ec6663a18bf6ac825736533b2",
        conf_b: "c2370e1bf813b086dff0d834e74425a06e6390f48f5411900276dcccc5a297ec",
    },
    Vector {
        id_a: "",
        id_b: "",
        w: "7bf46c454b4c1b25799527d896508afd5fc62ef4ec59db1efb49113063d70cca",
        x: "8cef65df64bb2d0f83540c53632de911b5b24b3eab6cc74a97609fd659e95473",
        y: "d7a66f64074a84652d8d623a92e20c9675c61cb5b4f6a0063e4648a2fdc02d53",
        p_a: concat!(
            "04a65b367a3f613cf9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f4",
            "6ca1ef6a676598889fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d",
            "66"
        ),
        p_b: concat!(
            "04589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc0494",
            "662eea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6f5",
            "8d"
        ),
        tt: concat!(
            "00000000000000000000000000000000410000000000000004a65b367a3f613c",
            "f9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f46ca1ef6a67659888",
            "9fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d6641000000000000",
            "0004589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc04",
            "94662eea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6",
            "f58d4100000000000000041a3c03d51b452537ca2a1fea6110353c6d5ed483c4",
            "f0f86f4492ca3f378d40a994b4477f93c64d928edbbcd3e85a7c709b7ea73ee9",
            "7986ce3d1438e13554377220000000000000007bf46c454b4c1b25799527d896",
            "508afd5fc62ef4ec59db1efb49113063d70cca"
        ),
        hash_tt: "fc6374762ba5cf11f4b2caa08b2cd1b9907ae0e26e8d6234318d91583cd74c86",
        ke: "fc6374762ba5cf11f4b2caa08b2cd1b9",
        ka: "907ae0e26e8d6234318d91583cd74c86",
        kc_a: "5dbd2f477166b7fb6d61febbd77a5563",
        kc_b: "7689b4654407a5faeffdc8f18359d8a3",
        conf_a: "dfb4db8d48ae5a675963ea5e6c19d98d4ea028d8e898dad96ea19a80ade95dca",
        conf_b: "d0f0609d1613138d354f7e95f19fb556bf52d751947241e8c7118df5ef0ae175",
    },
];

fn run_vector(v: &Vector) {
    let test = TestScalars {
        w: Some(scalar_from_hex(v.w)),
        x: Some(scalar_from_hex(v.x)),
        y: Some(scalar_from_hex(v.y)),
    };
    let mut a = Spake2Initiator::new_with_params(&[], v.id_a.as_bytes(), v.id_b.as_bytes(), &[])
        .with_scalars(&test);
    let mut b = Spake2Responder::new_with_params(&[], v.id_a.as_bytes(), v.id_b.as_bytes(), &[])
        .with_scalars(&test);

    let p_a = a.generate_message();
    assert_eq!(hex(&p_a), v.p_a, "pA");

    let (p_b, secrets_b, c_b) = b.process_intro(&p_a).expect("responder intro");
    assert_eq!(hex(&p_b), v.p_b, "pB");
    assert_eq!(hex(&secrets_b.transcript), v.tt, "TT");

    let (secrets_a, c_a) = a.process_response(&p_b).expect("initiator finish");
    assert_eq!(hex(&c_a), v.conf_a, "cA");
    assert_eq!(hex(&c_b), v.conf_b, "cB");

    // Key schedule: Hash(TT) split, HKDF confirmation keys, HMACs.
    assert_eq!(hex(&secrets_a.ke), v.ke, "Ke");
    assert_eq!(hex(&secrets_a.ka), v.ka, "Ka");
    assert_eq!(hex(&secrets_a.kc_a), v.kc_a, "KcA");
    assert_eq!(hex(&secrets_a.kc_b), v.kc_b, "KcB");
    let digest = Sha256::digest(&secrets_a.transcript);
    assert_eq!(hex(&digest), v.hash_tt, "Hash(TT)");

    a.verify_confirmation(&secrets_a, &c_b)
        .expect("A checks cB");
    b.verify_confirmation(&secrets_b, &c_a)
        .expect("B checks cA");

    // Both parties derive identical secrets.
    assert_eq!(secrets_a.ke, secrets_b.ke);
    assert_eq!(secrets_a.transcript, secrets_b.transcript);
}

#[test]
fn rfc9382_vector_1_a_server_b_client() {
    run_vector(&VECTORS[0]);
}

#[test]
fn rfc9382_vector_2_a_empty_b_client() {
    run_vector(&VECTORS[1]);
}

#[test]
fn rfc9382_vector_3_a_server_b_empty() {
    run_vector(&VECTORS[2]);
}

#[test]
fn rfc9382_vector_4_both_identities_empty() {
    run_vector(&VECTORS[3]);
}

#[test]
fn reject_public_value_that_is_not_a_curve_point() {
    let mut a = Spake2Initiator::new(b"code");
    let _ = a.generate_message();
    let mut b = Spake2Responder::new(b"code");
    let bad = [0u8; 65]; // 0x00 prefix is not a valid SEC1 encoding
    assert!(b.process_intro(&bad).is_err());
}
