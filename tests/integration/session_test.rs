// Integration tests for session flow
// These tests require Redis to be running
// Run with: cargo test --test integration --features test

#[cfg(test)]
mod tests {
    use nameshare_backend::{
        config::Config,
        services::{code_generator::CodeGenerator, session::SessionService},
        state::AppState,
    };
    use uuid::Uuid;

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_session_create_and_retrieve() {
        // This test requires Redis to be running
        // In CI/CD, use docker-compose to spin up Redis
        
        let config = Config::from_env().expect("Failed to load config");
        let state = AppState::new(config).await.expect("Failed to create state");

        // Generate code
        let code = CodeGenerator::generate_unique_code(&state)
            .await
            .expect("Failed to generate code");

        // Create session
        let session_id = Uuid::new_v4();
        let creator_id = Uuid::new_v4().to_string();
        let code_hmac = nameshare_backend::services::hmac::compute_code_hmac(
            &state.hmac_key,
            &code,
        );

        let session = nameshare_backend::models::session::Session::new(
            session_id,
            code_hmac,
            creator_id,
            600,
            true,
        );

        SessionService::create_session(&state, session.clone(), &code)
            .await
            .expect("Failed to create session");

        // Retrieve session
        let retrieved = SessionService::get_session(&state, &session_id)
            .await
            .expect("Failed to retrieve session");

        assert_eq!(retrieved.session_id, session.session_id);
        assert_eq!(retrieved.code_hmac, session.code_hmac);

        // Retrieve by code
        let retrieved_by_code = SessionService::get_session_by_code(&state, &code)
            .await
            .expect("Failed to retrieve session by code");

        assert_eq!(retrieved_by_code.session_id, session.session_id);
    }
}
