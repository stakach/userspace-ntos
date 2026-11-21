//! A component lane's external token stack holds user-callback tokens and service-wait tokens
//! together, and admission compares them (`validate_callback_below_service` refuses a callback
//! token equal to the service token). Boot 44836920548 exited win32k-dispatch-retained on
//! explorer's nested 0x1030: lane 48's stack was [0x2f3, 0x2f9, 0x2f9]. The callback token came
//! from the user-callback counter and the service-wait token from the service-wait issuer; the
//! two independent counters had both reached 0x2f9. Every lane external token comes from one
//! issuer.

const GLUE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");

#[test]
fn user_callback_tokens_come_from_the_lane_token_issuer() {
    assert!(!GLUE.contains("USER_CALLBACK_TRANSFER_IDS"),
        "no second counter issues lane external tokens");
    let begin = GLUE.find("let mut token_user_sid = [0u8; nt_user_callback::CLIENT_TOKEN_USER_SID_MAX];")
        .expect("callback frame construction");
    let before = &GLUE[..begin];
    let issue = before.rfind("next_service_wait_token()").expect("callback token issuance");
    assert!(begin - issue < 600, "the callback frame's external token is the shared issuer's");
}
