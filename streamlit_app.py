import os
import json
import streamlit as st
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import openai
from datetime import datetime, timedelta

# Google Calendar API settings
SCOPES = ['https://www.googleapis.com/auth/calendar', 'https://www.googleapis.com/auth/userinfo.profile']
CLIENT_SECRETS_FILE = "credentials.json"
REDIRECT_URI = "https://spedatox.streamlit.app"  # Your Streamlit app URL

# OpenAI API key
openai.api_key = 'YOUR_OPENAI_API_KEY'

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

def authenticate(username):
    creds = load_credentials(username)
    
    if creds and creds.valid:
        return creds
    elif creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        save_credentials(creds, username)
        return creds
    else:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
        st.sidebar.markdown(f"Google Hesabınızla Giriş Yapmak için [burayı]({auth_url}) tıklayın.")
        st.sidebar.info("Giriş işleminden sonra kullanıcı adınızı yazıp kullanmaya başlayabilirsiniz")
        
        # Check the URL parameters when the OAuth flow is completed
        if st.experimental_get_query_params().get('code'):
            query_params = st.experimental_get_query_params()
            try:
                flow.fetch_token(code=query_params['code'][0])
                creds = flow.credentials
                save_credentials(creds, username)
                st.success(f"{username}, login successful!")
                st.experimental_set_query_params()  # Clear the query parameters to simulate a rerun
                return creds
            except Exception as e:
                st.error(f"Error during authorization: {e}")
        elif st.experimental_get_query_params().get('error'):
            st.error(f"Error during authorization: {st.experimental_get_query_params()['error'][0]}")
    return None
    
def get_calendar_service(creds):
    service = build('calendar', 'v3', credentials=creds)
    return service

def list_events(service):
    now = datetime.utcnow().isoformat() + 'Z'  # 'Z' indicates UTC time
    one_week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat() + 'Z'
    one_month_later = (datetime.utcnow() + timedelta(days=30)).isoformat() + 'Z'
    events_result = service.events().list(
        calendarId='primary',
        timeMin=one_week_ago,
        timeMax=one_month_later,
        maxResults=50,
        singleEvents=True,
        orderBy='startTime'
    ).execute()
    events = events_result.get('items', [])
    return events

def add_event(service, summary, start_time, end_time):
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
    event = service.events().insert(calendarId='primary', body=event).execute()
    return event

def summarize_events(events):
    event_descriptions = "\n".join([
        f"{event['start'].get('dateTime', event['start'].get('date'))}: {event['summary']}"
        for event in events
    ])
    prompt = f"Aşağıdaki etkinlikleri ilk önce okunaklı bir liste olarak (Örneğin: 1 Ocak 2000 - (ETKİNLİK ADI)) yazıp daha sonrasında kısa bir şekilde özetle, esprili olabilirsin, {even[...]
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content.strip()

def convert_time_to_iso_format(time_str):
    prompt = f"Convert the following time '{time_str}' to ISO 8601 format."
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content.strip()

def generate_response(user_input, user_name):
    if not user_input:
        return "No user input provided."

    content = f"Adın Speda Ahmet Erol Bayrak Tarafından Geliştirilen Bir Yapay Zekasın. Kod yazabilir, metin oluşturabilir, bir yapay zeka asistanının yapabildiği neredeyse herşeyi yapabilirsin. Kullanıcının adı {user_name}"
    prompt = f"{content}\n\n{user_input}"

    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": prompt}]
    )
    return response.choices[0].message.content.strip()

def get_user_info(creds):
    user_info_service = build('oauth2', 'v2', credentials=creds)
    user_info = user_info_service.userinfo().get().execute()
    return user_info['name']

def main():
    st.title("Speda Takvim Asistanı")
    st.caption("Google Takvimi entegre eden Chatbot")

    if 'messages' not in st.session_state:
        st.session_state.messages = []

    with st.sidebar:
        username = st.text_input("Lütfen kullanıcı adınızı girin:")
        if username:
            creds = authenticate(username)
        else:
            creds = None

    if creds:
        service = get_calendar_service(creds)
        user_name = get_user_info(creds)
        st.sidebar.success(f"Hoşgeldin, {user_name}!")

        user_input = st.chat_input("What is up?")
        if user_input:
            st.session_state.messages.append({"role": "user", "content": user_input})

            if "ekle" in user_input.lower():
                st.session_state.show_event_form = True

            if "show_event_form" in st.session_state and st.session_state.show_event_form:
                with st.chat_message("assistant"):
                    st.subheader("Etkinlik Bilgilerini Girin")
                    summary = st.text_input("Etkinlik Başlığı:")
                    start_date = st.date_input("Başlangıç Tarihi")
                    start_time = st.time_input("Başlangıç Saati")
                    end_date = st.date_input("Bitiş Tarihi")
                    end_time = st.time_input("Bitiş Saati")
                    if st.button("Etkinliği Ekle"):
                        try:
                            start_datetime = datetime.combine(start_date, start_time).isoformat()
                            end_datetime = datetime.combine(end_date, end_time).isoformat()
                            event = add_event(service, summary, start_datetime, end_datetime)
                            st.success(f"Etkinlik başarıyla eklendi: [Etkinliğe Git]({event.get('htmlLink')})")
                            st.session_state.show_event_form = False
                        except Exception as e:
                            st.error(f"Etkinlik eklenirken bir hata oluştu: {e}")
                    else:
                        st.session_state.show_event_form = True

            elif "liste" in user_input.lower():
                try:
                    events = list_events(service)
                    if not events:
                        st.info("Yakın zamanda hiçbir etkinlik bulunamadı.")
                    else:
                        st.subheader("Mevcut Etkinlikler")
                        response = summarize_events(events)
                        st.session_state.messages.append({"role": "assistant", "content": response})
                except Exception as e:
                    st.error(f"Etkinlikler listelenirken bir hata oluştu: {e}")
            else:
                response = generate_response(user_input, user_name)
                st.session_state.messages.append({"role": "assistant", "content": response})

        for message in st.session_state.messages:
            if message["role"] == "user":
                with st.chat_message("user"):
                    st.write(message['content'])
            else:
                with st.chat_message("assistant"):
                    st.write(message['content'])

if __name__ == '__main__':
    main()
