![Locker Password Manager](https://s.locker.io/assets/locker_private_email.png "Locker Password Manager")

-------------------

# Maily

Maily is the core of [Locker Private Email](https://locker.io/private-email) that allows users to create email
aliases `@maily.org` to keep their original email addresses hidden when using the internet. With Maily, users can create
unique email aliases for different purposes, such as online shopping, social media, or business contacts, and manage
them within one secure inbox.

## Development

Maily is written in Python 3.10 and utilizes a stack of AWS (Amazon Web Services) to process and store messages
including S3, SES, and SQS.

## Run locally

1. Clone and change to the directory:

    ```shell
    git clone https://github.com/lockerpm/maily.git
    cd maily
    ```

2. Create and activate a virtual environment:

   Unix based systems:
   ```sh
   virtualenv env
   source env/bin/activate
   ```
   Windows:
   ```sh
   python -m venv env
   source env/Scripts/activate
   ```

3. Install Python requirements:

   ```sh
   pip install -r requirements.txt
   ```

4. Set environment variables Maily requires a list of variables defined in [the config file](/src/maily/config.py). You
   should set the following variables:

   | **Variable**       | **Description**                                                                                                             | **Example**       |
      |--------------------|-----------------------------------------------------------------------------------------------------------------------------|-------------------|
   | RELAY_DOMAINS      | A list of relay domains                                                                                                     | [ "maily.org"]    |
   | REPLY_EMAIL        | The email used for replying                                                                                                 | replies@maily.org |
   | RELAY_FROM_ADDRESS | The relay email address                                                                                                     | relay@maily.org   |
   | LOCKER_TOKEN_API   | The token to authenticate with the Locker server. You should implement your own backend server to serve requests from Maily |                   |
   | AWS_REGION         | The default region of AWS S3                                                                                                | us‑east‑1          |
   | AWS_SES_CONFIG_SET | Maily uses AWS SES to send emails, so you have configure the configure set in SES                                           |                   |
   | AWS_SNS_TOPIC      | The SNS topic of AWS for getting new notifications                                                                          |                   |
   | AWS_SQS_URL        | The SQS URL of AWS for getting tasks from the queue                                                                         |                   |


   The variables can be set by the command `export NAME=VALUE`

5. Run the prgram
   ```shell
   python manage.py
   ```

### Docker

In the production environment, Maily is packaged in Docker containers and run on Kubernetes (k8s). You can run an
instance of Maily as following

```shell
docker build -t maily .
docker run maily 
```

## API Access

We published the docs for using Locker Private
Email [here](https://docs.locker.io/docs/category/private-email-addresses). You can use it to create unlimited email
aliases without building Maily

## Credits

Maily is inspired by [Mozilla Private Relay](https://github.com/mozilla/fx-private-relay) and uses some of its code for
message handling. Thanks to Mozilla for the awesome project.

## License

[GPLv3](./LICENSE)
