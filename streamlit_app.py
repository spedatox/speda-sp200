def authenticate(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check if username exists
    if username not in USER_DATABASE:
        # Save new user
        save_user(username, password)
        st.sidebar.success("Yeni kullanıcı kaydedildi ve giriş yapıldı.")
    elif USER_DATABASE[username] != hashed_password:
        st.sidebar.error("Geçersiz kullanıcı adı veya şifre.")
        return None, None

    creds = load_credentials(username)

    if creds and creds.valid:
        kullanici_adi = get_google_user_name(creds)  # Function to get the user's name from Google credentials
        st.sidebar.success(f"Hoşgeldin {kullanici_adi}!")
        return creds, kullanici_adi
    elif creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        save_credentials(creds, username)
        kullanici_adi = get_google_user_name(creds)
        st.sidebar.success(f"Hoşgeldin {kullanici_adi}!")
        return creds, kullanici_adi
    else:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
        st.sidebar.markdown(f"Click [here]({auth_url}) to log in with your Google account")
        st.sidebar.info("The app will log in automatically after authorization.")

        # Check the URL parameters when the OAuth flow is completed
        query_params = st.experimental_get_query_params()  # Accessing query parameters correctly
        if 'code' in query_params:
            try:
                flow.fetch_token(code=query_params['code'][0])
                creds = flow.credentials
                save_credentials(creds, username)
                kullanici_adi = get_google_user_name(creds)
                st.sidebar.success(f"Hoşgeldin {kullanici_adi}!")
                st.experimental_set_query_params()  # Clear the query parameters to simulate a rerun
                return creds, kullanici_adi
            except Exception as e:
                st.sidebar.error(f"Error during authorization: {e}")
        elif 'error' in query_params:
            st.sidebar.error(f"Error during authorization: {query_params['error'][0]}")
    return None, None
