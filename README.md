# evacora
evacora is a stateless password manager. It calculates passwords on the fly, using the information you provide along with your master password. Your passwords are never stored anywhere. Because passwords are never stored you don't need to sync them, meaning you don't need an internet connection to send them to a cloud server, and don't have to sync files between devices.

## Philosophy and goal
evacora uses a stateless design in order to achieve two things: a fully independent system and abolishing the requirement for syncing.

While the evacora CLI allows you to use stateful files to ease usage on devices you frequently use, the files are designed to never store information you cannot easily remember and the CLI is designed to display the stored information on each generator run. That way if you ever do not have the file on hand, you should still be able to remember the details for your most frequently used accounts, which should help in the majority of the cases. Through this design evacora maintains the benefits of statelessness while allowing easy and quick access on frequently used devices.

Because of this philosophy evacora doesn't allow you to store information such as a custom charsets for specific accounts. This sort of information isn't trivial to remember and evacora doesn't allow you to make yourself dependant on maintaining state.

One problem that stateless password managers frequently face is that services impose byzantine restrictions on password length or charset composition. evacora addresses this issue by ... recommending not to use evacora for such services. These kinds of services tend to be old, hardly maintained, and do not require frequent logins. As such, the stateless nature of evacora doesn't really offer any benefits for these services. Therefore, using a stateful password manager for these services with unreasonable restrictions while using evacora for services that need to be accessed frequently and from anywhere is recommended.

## How to use evacora
You can use evacora by running the CLI with nodeJS or by using the [web version](https://mahakadema.github.io/evacora). The CLI runs faster and allows for local storage of accounts and password checking for your master password.

To generate a password, enter a service name and master password. A username can be used to manage multiple accounts. A salt can be specified to change the generated password, which can be used for password resets.

To use the CLI, download the latest release zip, unzip the file and run `npm install` and `node .` inside the directory.

## Using the CLI
To set up the CLI, run `node . --create-file ./data` inside the evacora directory to initialize a new data file. You can then use `node . --file ./data` to use the data file to enable password checking and register services and users under the `Edit data` option.

The CLI takes these optional flags on startup:
- `--help`, `-h` Displays a help page
- `--file`, `-f <path>` A path to a data file
- `--create-file <path>` A path to create a new data file at
- `--charset`, `-m <charset>` Define up to 64 characters to be used in the password, intended to circumvent character restrictions.
- `--verbose`, `-v` Logs verbosely
- `--timeout`, `-t <seconds>` Define an inactivity timeout after which to close the app
- `--copy`, `-c` Copies the password into the clipboard for 15 seconds, instead of printing it into the console
- `--show-password`, `-s` Repeatable; when used once, the master password is masked; when used twice, the password is shown; when omitted, the password is hidden
- `--quick`, `-q` Skip the confirmation prompt on data deletion
- `--import <path>` Specify a path to an exported file. You will be given the option to add the imported data to your data or replace it

This repository also includes an example data file (master password is 'password1'). Running `node . -f ./example` and answering `password1`, `Get passwords`, `example.com` and `admin` to the prompts will generate the password for `admin@example.com` with a salt of `abc`, as this salt was specified in the data file.

You can also define a script to automatically launch evacora with the preferred flags. You can then execute this script from your desktop or another easily accessible place.
```
node /path/to/evacora -s -f /path/to/data.json -t 180
```

## What evacora does to keep your passwords secure
evacora is build from the ground up with security in mind, which is why every part of evacora is designed to keep you as safe as possible:
- Sessions are terminated as quickly as possible. By default, sessions terminate after 120 seconds of inactivity.
- evacora uses argon2id with 256 MiB RAM cost and 20 iterations. This means that even an 8 character alphanumeric master password will cost tens of millions USD in electricity to crack. Of course, this is not an excuse to use a weak master password.
- Local data is entirely encrypted using the master password with AES-256-GCM.

## Is this more secure than solutions maintaining state?
Stateless password managers are often advertised to be inherently more secure, argueing that no state is more secure than an encrypted state. That is not true. (because that's what the word "encrypted" means) A properly implemented password manager that maintains state is just as good as a stateless solution. However, stateful solutions often make themselves vulnerable by maintaining a session as to avoid requiring the user to type out the master password on every login. This is a convenient feature, but makes the solution vulnerable to session stealing. Designing around statelessness makes it much easier to not fall in such pitfalls. However, stateless solutions are not without flaws either:

## No storage does not mean zero risk
Just because evacora does not require you to store your passwords anywhere does not mean you cannot have your passwords stolen. You will most likely copy the password to your clipboard to log into the service. Therefore any application able to read your clipboard may read out the passwords. An open website may read your clipboard if you focus the tab, any browser extentions may read your clipboard and any application running on your machine with sufficient permissions may read your keystrokes, allowing it to even read out your master password. It is therefore advised to never use evacora on devices you do not trust, to clear the clipboard after you logged in (and to disable clipboard history), and to make sure you trust your browser addons.

## Choosing a naming and usage scheme
It is advised to start using a common naming and usage scheme early on to avoid guessing games on whether the service name was just `service`, `service.com` or `login.service.com`. Which scheme to use is intentionally left at the discretion of the user, but an example scheme may be something like this:
- Only use the domainname (`example` instead of `example.com`) for services to allow for non-website based services
- Usernames are the full email (`user@web.mail`) or, if no email was used, the full username
- Providing only the service name (username left empty / no users registered) will only be done if it's obvious that no other account for the same service will ever be registered (e.g. web services like "Look at cat pictures" that require you to register an account to view kitties for some reason)
- Salts are only used if a password is compromised. As salt, use the current year.
- If the default character set gets rejected by the website, use `[A-Za-z0-9!+]`
- If the generated password gets rejected by the website because of something like "Your password needs to contain at least one number", append a 0 for numbers and ! for special characters to the end
- If the generated password gets rejected because it is too long, go down to exactly 16 characters, if that is still too long, 12
If these rules are enforced consistently, nearly all guessing games should be eliminated.
