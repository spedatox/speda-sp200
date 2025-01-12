# Add the necessary imports
import os
import json
import streamlit as st
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import openai
from datetime import datetime, timedelta
import hashlib

# Google Calendar API settings
SCOPES = ['https://www.googleapis.com/auth/calendar', 'https://www.googleapis.com/auth/userinfo.profile']
CLIENT_SECRETS_FILE = "credentials.json"
REDIRECT_URI = "https://spedatox.streamlit.app"  # Your Streamlit app URL

# OpenAI API key
openai.api_key = 'YOUR_OPENAI_API_KEY'  # Replace with your actual OpenAI API key

# Load user database from file
USER_DATABASE_FILE = 'user_database.json'
if os.path.exists(USER_DATABASE_FILE):
    with open(USER_DATABASE_FILE, 'r') as f:
        USER_DATABASE = json.load(f)
else:
    USER_DATABASE = {}

def save_user_database():
    with open(USER_DATABASE_FILE, 'w') as f:
        json.dump(USER_DATABASE, f)

def save_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    USER_DATABASE[username] = hashed_password
    save_user_database()

# User-based token file
def get_token(username):
    return f"{username}_token.json"

def load_credentials(username):
    token_file = get_token(username)
    creds = None
    if os.path.exists(token_file):
        with open(token_file, 'r') as token:
            creds_data = json.load(token)
            creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
    return creds

def save_credentials(creds, username):
    token_file = get_token(username)
    with open(token_file, 'w') as token:
        token.write(creds.to_json())

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
        query_params = st.query_params()
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

def get_google_user_name(creds):
    if not creds or not creds.valid:
        raise ValueError("Invalid credentials")
        
    service = build('oauth2', 'v2', credentials=creds)
    user_info = service.userinfo().get().execute()
    return user_info['name']

def get_calendar_list(creds):
    service = build('calendar', 'v3', credentials=creds)
    calendar_list = service.calendarList().list().execute()
    return calendar_list.get('items', [])

def get_calendar_service(creds):
    service = build('calendar', 'v3', credentials=creds)
    return service

def list_events(service, calendar_id):
    now = datetime.utcnow().isoformat() + 'Z'  # 'Z' indicates UTC time
    one_week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat() + 'Z'
    one_month_later = (datetime.utcnow() + timedelta(days=30)).isoformat() + 'Z'
    events_result = service.events().list(
        calendarId=calendar_id,
        timeMin=one_week_ago,
        timeMax=one_month_later,
        maxResults=50,
        singleEvents=True,
        orderBy='startTime'
    ).execute()
    events = events_result.get('items', [])
    return events

def add_event(service, calendar_id, summary, start_time, end_time):
    event = {
        'summary': summary,
        'start': {
            'dateTime': start_time,
            'timeZone': 'Europe/Istanbul',
        },
        'end': {
            'dateTime': end_time,
            'timeZone': 'Europe/Istanbul',
        },
    }
    event = service.events().insert(calendarId=calendar_id, body=event).execute()
    return event

def summarize_events(events):
    event_descriptions = "\n".join([
        f"{event['start'].get('dateTime', event['start'].get('date'))}: {event['summary']}"
        for event in events
    ])
    prompt = f"Aşağıdaki etkinlikleri ilk önce okunaklı bir liste olarak (Örneğin: 1 Ocak 2000 - ETKİNLİK ADI) yazıp daha sonrasında kısa bir şekilde özetle:\n\n{event_descriptions}"
    
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content.strip()
    
def convert_time_to_iso_format(time_str):
    prompt = f"Convert the following time '{time_str}' to ISO 8601 format."
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content.strip()

def generate_response(user_input, kullanici_adi, messages):
    if not user_input:
        return "No user input provided."

    content = f"Senin adın Speda. Ahmet Erol Bayrak Tarafından Geliştirilen Bir Yapay Zekasın. Kod yazabilir, metin oluşturabilir, bir yapay zeka asistanının yapabildiği neredeyse herşeyi yap[...]"
    prompt = f"{content}\n\n{user_input}"

    try:
        client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        all_messages = messages + [{"role": "user", "content": prompt}]
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=all_messages
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error invoking OpenAI API: {e}")
        return "An error occurred while generating the response."

def main():
    st.title("Speda Takvim Asistanı")
    st.caption("Google Takvimi entegre eden Chatbot")

    if 'messages' not in st.session_state:
        st.session_state.messages = []
        print("Initialized session state messages")

    if 'creds' not in st.session_state:
        st.session_state.creds = None
        print("Initialized session state creds")

    if 'kullanici_adi' not in st.session_state:
        st.session_state.kullanici_adi = None
        print("Initialized session state kullanici_adi")

    if 'show_form' not in st.session_state:
        st.session_state.show_form = False
        print("Initialized session state show_form")

    with st.sidebar:
        st.header("Kullanıcı Girişi")
        username = st.text_input("Lütfen kullanıcı adınızı girin:")
        password = st.text_input("Lütfen şifrenizi girin:", type="password")
        if st.button("Giriş Yap"):
            if username and password:
                creds, kullanici_adi = authenticate(username, password)
                st.session_state.creds = creds
                st.session_state.kullanici_adi = kullanici_adi
                print(f"Authenticated user: {kullanici_adi}")

    creds = st.session_state.creds
    kullanici_adi = st.session_state.kullanici_adi

    if creds:
        service = get_calendar_service(creds)
        print("Obtained Google Calendar service")

        calendar_list = get_calendar_list(creds)
        calendar_ids = {calendar['summary']: calendar['id'] for calendar in calendar_list}
        selected_calendar = st.sidebar.selectbox("Takvim Seçin:", list(calendar_ids.keys()))
        print(f"Selected calendar: {selected_calendar}")

        if selected_calendar:
            selected_calendar_id = calendar_ids[selected_calendar]
        else:
            selected_calendar_id = 'primary'
            print("Defaulting to primary calendar")

        user_input = st.chat_input("Ne yapmak istiyorsunuz?")
        if user_input:
            st.session_state.messages.append({"role": "user", "content": user_input})
            print(f"User input: {user_input}")

            if "liste" in user_input.lower():
                try:
                    events = list_events(service, selected_calendar_id)
                    if not events:
                        st.session_state.messages.append({"role": "assistant", "content": "Yakın zamanda hiçbir etkinlik bulunamadı."})
                    else:
                        response = summarize_events(events)
                        st.session_state.messages.append({"role": "assistant", "content": "### Mevcut Etkinlikler\n" + response})
                    print("Listed events")
                except Exception as e:
                    st.error(f"Etkinlikler listelenirken bir hata oluştu: {e}")
                    print(f"Error listing events: {e}")
            elif "ekle" in user_input.lower():
                st.session_state.messages.append({"role": "assistant", "content": "Lütfen etkinlik bilgilerini girin:"})
                st.session_state.show_form = True
                print("Prompting user to enter event details")

        for message in st.session_state.messages:
            if message["role"] == "user":
                with st.chat_message("user"):
                    st.write(message['content'])
            else:
                with st.chat_message("assistant"):
                    st.write(message['content'])
                    if st.session_state.show_form and message["content"] == "Lütfen etkinlik bilgilerini girin:":
                        with st.form("add_event_form_from_prompt", clear_on_submit=False):
                            summary = st.text_input("Etkinlik Başlığı:")
                            start_date = st.date_input("Başlangıç Tarihi")
                            start_time = st.time_input("Başlangıç Saati")
                            end_date = st.date_input("Bitiş Tarihi")
                            end_time = st.time_input("Bitiş Saati")
                            submitted_event = st.form_submit_button("Etkinliği Ekle")

                            if submitted_event:
                                try:
                                    if not summary:
                                        st.error("Etkinlik başlığı boş bırakılamaz.")
                                    else:
                                        start_datetime = datetime.combine(start_date, start_time).isoformat()
                                        end_datetime = datetime.combine(end_date, end_time).isoformat()
                                        event = add_event(service, selected_calendar_id, summary, start_datetime, end_datetime)
                                        st.session_state.messages.append({"role": "assistant", "content": f"Etkinlik başarıyla eklendi: [Etkinliğe Git]({event.get('htmlLink')})"})
                                        st.session_state.show_form = False
                                        print("Event added successfully")
                                except Exception as e:
                                    st.error(f"Etkinlik eklenirken bir hata oluştu: {e}")
                                    print(f"Error adding event: {e}")

if __name__ == '__main__':
    main()
