
# Streamlit Public Version (v2) – Low Quality Site Detector

## What’s fixed in v2
- Accepts full URLs and redirects (e.g., `http://site.com/go?id=123`)
- Follows redirects and evaluates the **final URL**
- Normalizes and shows the **root/base domain** for the final verdict
- Trusted allowlist works on both input domain and redirected domain

## Deploy Publicly
1. Create a GitHub repository
2. Upload these files
3. Go to https://streamlit.io/cloud
4. Click "New App"
5. Select your repository
6. Deploy

You will get a public link like:
https://your-app-name.streamlit.app
