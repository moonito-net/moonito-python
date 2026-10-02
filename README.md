# moonito-python

Official Python SDK for [Moonito](https://moonito.net) — a smart analytics and visitor filtering platform designed to protect your website from unwanted traffic, bots, and malicious activity while providing deep visitor insights.

**moonito-python** is a lightweight Python SDK for integrating your web application with the Moonito Visitor Analytics API.

It allows you to:

- Analyze and monitor web traffic intelligently
- Filter out bots, crawlers, and unwanted visitors
- Get real-time visitor behavior insights
- Protect APIs, landing pages, and web apps automatically

Compatible with Flask, Django, FastAPI, and other Python web frameworks.

`evaluate_visitor` never raises. If the check cannot run (the API is unreachable, or refuses because a plan expired) it returns `None`, the visitor is let through, and the reason goes to the `moonito` logger. Moonito never turns into an error page on your site.

## 📦 Installation

```bash
pip install moonito
```

## 🚀 Quick Start

### Flask Example

```python
from flask import Flask, request, Response
from moonito import VisitorTrafficFiltering, Config

app = Flask(__name__)

# Initialize Moonito
client = VisitorTrafficFiltering(Config(
    is_protected=True,
    api_public_key="YOUR_PUBLIC_KEY",
    api_secret_key="YOUR_SECRET_KEY",
    unwanted_visitor_to="https://example.com/blocked",  # URL or HTTP status code
    unwanted_visitor_action=1  # 1 = Redirect, 2 = Iframe, 3 = Load content
))

@app.before_request
def check_visitor():
    """Middleware to check visitors before processing requests"""
    result = client.evaluate_visitor(request)
    
    if result:
        content = result['content']
        
        if isinstance(content, int):
            return Response(status=content)
        
        return Response(content, mimetype='text/html')

@app.route('/')
def home():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run(port=8080)
```

### Django Example

```python
# middleware.py
from moonito import VisitorTrafficFiltering, Config
from django.http import HttpResponse

class MoonitoMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Initialize Moonito
        self.client = VisitorTrafficFiltering(Config(
            is_protected=True,
            api_public_key="YOUR_PUBLIC_KEY",
            api_secret_key="YOUR_SECRET_KEY",
            unwanted_visitor_to="https://example.com/blocked",
            unwanted_visitor_action=1
        ))

    def __call__(self, request):
        # Check visitor
        result = self.client.evaluate_visitor(request)
        
        if result:
            content = result['content']
            
            if isinstance(content, int):
                return HttpResponse(status=content)
            
            return HttpResponse(content)
        
        response = self.get_response(request)
        return response
```

Add to `settings.py`:
```python
MIDDLEWARE = [
    'your_app.middleware.MoonitoMiddleware',
    # ... other middleware
]
```

### FastAPI Example

```python
from fastapi import FastAPI, Request, Response
from starlette.concurrency import run_in_threadpool
from moonito import VisitorTrafficFiltering, Config

app = FastAPI()

# Initialize Moonito
client = VisitorTrafficFiltering(Config(
    is_protected=True,
    api_public_key="YOUR_PUBLIC_KEY",
    api_secret_key="YOUR_SECRET_KEY",
    unwanted_visitor_to="https://example.com/blocked",
    unwanted_visitor_action=1
))

@app.middleware("http")
async def moonito_middleware(request: Request, call_next):
    """Middleware to check visitors"""
    # In a thread, so a slow decision never stalls your other requests.
    result = await run_in_threadpool(client.evaluate_visitor, request)
    
    if result:
        content = result['content']
        
        if isinstance(content, int):
            return Response(status_code=content)
        
        return Response(content=content, media_type="text/html")
    
    response = await call_next(request)
    return response

@app.get("/")
def read_root():
    return {"message": "Hello World"}
```

## ⚙️ Configuration

| Field | Type | Description |
|-------|------|-------------|
| `is_protected` | `bool` | Enable (`True`) or disable (`False`) protection |
| `api_public_key` | `str` | Your Moonito API public key (required) |
| `api_secret_key` | `str` | Your Moonito API secret key (required) |
| `unwanted_visitor_to` | `str` | URL to redirect unwanted visitors or HTTP error code |
| `unwanted_visitor_action` | `int` | Action for unwanted visitors: 1 = Redirect, 2 = Iframe, 3 = Load content |

## 🔧 Manual Evaluation

For custom implementations or manual checking:

```python
from moonito import VisitorTrafficFiltering, Config

client = VisitorTrafficFiltering(Config(
    is_protected=True,
    api_public_key="YOUR_PUBLIC_KEY",
    api_secret_key="YOUR_SECRET_KEY"
))

# Manually evaluate a visitor
result = client.evaluate_visitor_manually(
    ip="8.8.8.8",
    user_agent="Mozilla/5.0",
    event="/home",
    domain="example.com"
)

if result['need_to_block']:
    print("Blocked visitor detected.")
```

## 💡 Use Cases

- Prevent fake signups and bot traffic
- Protect landing pages from ad click fraud
- Collect accurate visitor analytics
- Detect suspicious activity in real time

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies (uses Python standard library)
- Moonito API keys from [https://moonito.net](https://moonito.net)

## 🧪 Development

```bash
# Clone the repository
git clone https://github.com/moonito-net/moonito-python.git
cd moonito-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .
pip install pytest

# Run tests
pytest tests/
```

## 📄 License

MIT License © 2025 [Moonito](https://moonito.net)

## 🏷️ Keywords

python analytics sdk, moonito sdk, visitor filtering python, python bot protection, python traffic analytics, moonito python sdk, moonito api, website protection sdk python, moonito visitor analytics, python security sdk

## 🌐 Learn More

Visit [https://moonito.net](https://moonito.net) to learn more about:

- Visitor analytics
- Website traffic protection
- API-based bot and fraud filtering

**Moonito — Stop Bad Bots. Start Accurate Web Analytics.**