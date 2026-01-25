# tmp-services

Yo, wssupppp! 👋

Welcome to **tmp-services**. No fancy intro, just straight fire for your temporary service needs. We keep it lean and mean here.

## The Stacks (What I Cooked Up)

Here is exactly what you get inside. I made this to be efficient, yahhhh.

### 1. Browserless (The Infinite IP Glitch)
Here's the trick: I personally spawn a Github Codespace, grab that `wss://` connection string, and run my web scrapers through it.
* **Why?** No IP blacklisting, fam.
* **How?** Every time I do this, I get a fresh machine and a fresh IP. It’s a little manual, but totally worth it to stay under the radar.

### 2. Postgres + PgBouncer + Custom Provisioner
This setup is secure and stupid easy.
* **The Flow:** Postgres with a custom DB/User provisioner and PgBouncer for connection pooling.
* **Usage:** Just run `docker compose up -d`. Boom.
* **Note:** Just make sure you set a secure default admin password. Don't leave it default unless you want trouble, xD.

### 3. Redis
It's free real estate, bro. Google it. You can use this for hobby stuff or production. Just find an optimal expiration time and you're good to go. :p

## The Philosophy (Why I Built It Like This)
Listen, I always prefer those **$6 USD droplets**.

Whatever code you see here is extremely resource-efficient. If it ain't efficient, there's no point in coding it.
* Sure, I *could* code in Python + Kubernetes and over-engineer the heck out of it.
* **But real engineering is when you're restrained.**
* Wasting a client's money on Stage 1 or Stage 2 isn't good for the long term. Keep it cheap, keep it fast.

## How to roll
1.  **Grab the code:**
    ```bash
    git clone [https://github.com/b33lz3bubTH/tmp-services.git](https://github.com/b33lz3bubTH/tmp-services.git)
    ```

2.  **Slide into the directory:**
    ```bash
    cd tmp-services
    ```

3.  **Run that magic:**
    Check the docker-compose files, pick your poison, and execute.

## Peace Out ✌️
Use it wisely. Save resources.

---
*Made with 😎 by b33lz3bubTH*
