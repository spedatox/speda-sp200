# 🧠 Speda SP200 – Smart Calendar Assistant (Prototype)

**Speda SP200** is an early-stage prototype of a smart calendar assistant that connects with your **Google Calendar** and provides **natural language summaries**, **event listings**, and **quick event additions** — powered by OpenAI.

This is an unfinished prototype built with [Streamlit](https://streamlit.io/), intended as a proof-of-concept for future development in AI-assisted productivity tools.

---

## 🚀 Features (Prototype Capabilities)

- 🔐 **User login system** with simple local authentication (username & password)
- ✅ **Google OAuth2 integration** with persistent credentials
- 🗓️ **Calendar listing and selection**
- 📋 **Event listing** for past 7 days and next 30 days
- 🧠 **Natural language summary** of events via OpenAI GPT (`gpt-4o-mini`)
- ➕ **Event creation form** with datetime inputs
- 🗨️ **Chat-style interface**: enter commands like "listele" or "ekle" to trigger actions

---

## 📎 Project Status

> 🧪 This project is an **unfinished prototype** built under the code name **Speda SP200**.  
> It demonstrates core integration flows but lacks production-grade features like security, scalability, error handling, and UX polish.

---

## ⚙️ Technologies Used

- **Streamlit** – Web frontend
- **OpenAI API** – Event summarization (GPT-4o-mini)
- **Google Calendar API** – OAuth and calendar access
- **Python 3.10+**
- **Local JSON storage** – for user management and credential persistence

---

## 🔐 Setup Instructions

### 1. Install Requirements

```bash
pip install -r requirements.txt
