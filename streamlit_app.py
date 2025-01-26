import os
import json
import hashlib
import streamlit as st
import openai
from datetime import datetime, timedelta
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Google Calendar API settings
SCOPES = ['https://www.googleapis.com/auth/calendar', 'https://www.googleapis.com/auth/userinfo.profile']
CLIENT_SECRETS_FILE = "credentials.json"
REDIRECT_URI = "https://spedatox.streamlit.app"

# OpenAI API Key
openai.api_key = st.secrets["OPENAI_API_KEY"]

# Kullanıcı veritabanı
USER_DATABASE_FILE = 'user_database.json'
USER_DATABASE = {}
if os.path.exists(USER_DATABASE_FILE):
    with open(USER_DATABASE_FILE, 'r') as f:
        USER_DATABASE = json.load(f)

# Yardımcı Fonksiyonlar
def save_user_database():
    with open(USER_DATABASE_FILE, 'w') as f:
        json.dump(USER_DATABASE, f)

def save_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    USER_DATABASE[username] = hashed_password
    save_user_database()

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

def get_google_user_name(creds):
    if not creds or not creds.valid:
        raise ValueError("Geçersiz kimlik bilgileri")
    service = build('oauth2', 'v2', credentials=creds)
    user_info = service.userinfo().get().execute()
    return user_info['name']

# Kimlik Doğrulama
def authenticate(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if username not in USER_DATABASE:
        save_user(username, password)
        st.sidebar.success("Yeni kullanıcı kaydedildi ve giriş yapıldı.")
    elif USER_DATABASE[username] != hashed_password:
        st.sidebar.error("Geçersiz kullanıcı adı veya şifre")
        return None, None

    creds = load_credentials(username)

    if creds and creds.valid:
        kullanici_adi = get_google_user_name(creds)
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
        st.sidebar.markdown(f"[Google ile Giriş Yap]({auth_url})")
        st.sidebar.info("Yetkilendirme sonrası otomatik giriş yapılacaktır")

        query_params = st.experimental_get_query_params()
        if 'code' in query_params:
            try:
                auth_code = query_params['code'][0]
                flow.fetch_token(code=auth_code)
                creds = flow.credentials
                save_credentials(creds, username)
                kullanici_adi = get_google_user_name(creds)
                st.sidebar.success(f"Hoşgeldin {kullanici_adi}!")
                st.experimental_set_query_params()
                return creds, kullanici_adi
            except Exception as e:
                st.sidebar.error(f"Yetkilendirme hatası: {e}")
        return None, None

# Takvim İşlemleri
def get_calendar_service(creds):
    return build('calendar', 'v3', credentials=creds)

def get_calendar_list(creds):
    service = get_calendar_service(creds)
    calendar_list = service.calendarList().list().execute()
    return calendar_list.get('items', [])

def list_events(service, calendar_id):
    one_week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat() + 'Z'
    one_month_later = (datetime.utcnow() + timedelta(days=30)).isoformat() + 'Z'

    st.write(f"🔍 Etkinlikler aranıyor: {one_week_ago} - {one_month_later}")

    events_result = service.events().list(
        calendarId=calendar_id,
        timeMin=one_week_ago,
        timeMax=one_month_later,
        maxResults=50,
        singleEvents=True,
        orderBy='startTime'
    ).execute()

    st.write("🔍 Ham Google Takvim Yanıtı:")
    st.json(events_result)  # Debug

    return events_result.get('items', [])

def add_event(service, calendar_id, summary, start_time, end_time):
    event_body = {
        'summary': summary,
        'start': {'dateTime': start_time, 'timeZone': 'Europe/Istanbul'},
        'end': {'dateTime': end_time, 'timeZone': 'Europe/Istanbul'},
    }
    return service.events().insert(calendarId=calendar_id, body=event_body).execute()

# OpenAI Entegrasyonu
def summarize_events(events):
    if not events:
        st.error("❌ Özetlenecek etkinlik bulunamadı!")
        return None

    event_descriptions = "\n".join([
        f"{event['start'].get('dateTime', event['start'].get('date'))}: {event['summary']}"
        for event in events
    ])

    st.write("📝 Oluşturulan Prompt:")
    st.code(event_descriptions)  # Debug

    prompt = f"Aşağıdaki etkinlikleri tarih sırasına göre listeleyip özetle:\n\n{event_descriptions}"

    try:
        st.write("🔌 OpenAI API'sine bağlanılıyor...")
        client = openai.OpenAI(api_key=st.secrets["OPENAI_API_KEY"])

        response = client.chat_completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            timeout=20
        )

        st.write("✅ API Yanıtı Alındı!")
        st.json(response)  # Debug

        return response.choices[0].message["content"].strip()

    except openai.AuthenticationError as e:
        st.error(f"🔒 Kimlik Doğrulama Hatası: {e}")
    except openai.APITimeoutError as e:
        st.error(f"⏳ Zaman Aşımı: {e}")
    except openai.APIError as e:
        st.error(f"🚨 API Hatası [HTTP {e.status_code}]: {e.message}")
    except Exception as e:
        st.error(f"❌ Beklenmeyen Hata: {str(e)}")

    return None

# Ana Uygulama
def main():
    st.title("🗓️ Speda Takvim Asistanı")
    st.caption("Google Takvim Entegrasyonlu Akıllı Asistan")

    # Oturum Durumları
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    if 'creds' not in st.session_state:
        st.session_state.creds = None
    if 'kullanici_adi' not in st.session_state:
        st.session_state.kullanici_adi = None
    if 'show_form' not in st.session_state:
        st.session_state.show_form = False

    # Sidebar
    with st.sidebar:
        st.header("🔐 Giriş Yap")
        username = st.text_input("Kullanıcı Adı")
        password = st.text_input("Şifre", type="password")
        if st.button("Giriş Yap", type="primary"):
            if username and password:
                creds, kullanici_adi = authenticate(username, password)
                st.session_state.creds = creds
                st.session_state.kullanici_adi = kullanici_adi

    # Ana İçerik
    if st.session_state.creds:
        service = get_calendar_service(st.session_state.creds)
        calendar_list = get_calendar_list(st.session_state.creds)
        calendar_ids = {cal['summary']: cal['id'] for cal in calendar_list}
        selected_calendar = st.sidebar.selectbox("Takvim Seçin", list(calendar_ids.keys()))
        selected_calendar_id = calendar_ids.get(selected_calendar, 'primary')

        # Sohbet
        user_input = st.chat_input("Ne yapmak istiyorsunuz?")
        if user_input:
            st.session_state.messages.append({"role": "user", "content": user_input})

            if "liste" in user_input.lower():
                try:
                    events = list_events(service, selected_calendar_id)
                    if not events:
                        st.session_state.messages.append({
                            "role": "assistant", 
                            "content": "❌ Yakın zamanda hiç etkinlik bulunamadı"
                        })
                    else:
                        response = summarize_events(events)
                        if response:
                            st.session_state.messages.append({
                                "role": "assistant",
                                "content": f"## 📅 Etkinlik Özeti\n{response}"
                            })
                except Exception as e:
                    st.error(f"Etkinlik listeleme hatası: {str(e)}")

            elif "ekle" in user_input.lower():
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": "📅 Lütfen etkinlik bilgilerini girin:"
                })
                st.session_state.show_form = True

        # Mesajları Göster
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])

                if st.session_state.show_form and "Lütfen etkinlik bilgilerini girin" in message["content"]:
                    with st.form("etkinlik_formu"):
                        summary = st.text_input("Etkinlik Adı*", key="summary")
                        start_date = st.date_input("Başlangıç Tarihi*", key="start_date")
                        start_time = st.time_input("Başlangıç Saati*", key="start_time")
                        end_date = st.date_input("Bitiş Tarihi*", key="end_date")
                        end_time = st.time_input("Bitiş Saati*", key="end_time")

                        if st.form_submit_button("Etkinliği Ekle"):
                            if not summary:
                                st.error("Etkinlik adı zorunlu!")
                            else:
                                start = datetime.combine(start_date, start_time).isoformat()
                                end = datetime.combine(end_date, end_time).isoformat()
                                try:
                                    event = add_event(service, selected_calendar_id, summary, start, end)
                                    st.session_state.messages.append({
                                        "role": "assistant",
                                        "content": f"✅ Etkinlik eklendi: [Takvimde Görüntüle]({event.get('htmlLink')})"
                                    })
                                    st.session_state.show_form = False
                                except Exception as e:
                                    st.error(f"Etkinlik ekleme hatası: {str(e)}")

if __name__ == '__main__':
    main()
