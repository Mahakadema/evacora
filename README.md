# evacora
evacora is a stateless password manager. It calculates passwords on the fly, using the information you provide along with your master password. Your passwords are never stored anywhere. Because passwords are never stored you don't need to sync them, meaning you don't need an internet connection to send them to a cloud server, and don't have to sync files between devices.

## Philosophy and goal
evacora uses a stateless design in order to achieve two things: a fully independent system and abolishing the requirement for syncing.

While the evacora CLI allows you to use stateful files to ease usage on devices you frequently use, the files are designed to never store information you cannot easily remember and the CLI is designed to display the stored information on each generator run. That way if you ever do not have the file on hand, you should still be able to remember the details for your most frequently used accounts, which should help in the majority of the cases. Through this design evacora maintains the benefits of statelessness while allowing easy and quick access on frequently used devices.

Because of this design goal evacora doesn't allow you to store information such as a custom charsets for specific accounts. This sort of information isn't trivial to remember and evacora doesn't allow you to make yourself dependant on maintaining state.

## How to use evacora
You can use evacora by running the [CLI](https://github.com/Mahakadema/evacora/releases) with nodeJS or by using the [web version](https://mahakadema.github.io/evacora). The CLI runs faster and allows for local storage of accounts and password checking for your master password. The web version can also use older versions of the generation algorithm.

To generate a password, enter a service name and master password. A username can be used to manage multiple accounts. A salt can be specified to change the generated password, which can be used for password resets.

To use the CLI, download the latest release zip, unzip the file and run `npm install` and `node .` inside the directory.

## Using the CLI
To set up the CLI, run `node . --create-file ./data` inside the evacora directory to initialize a new data file. You can then use `node . --file ./data` to use the data file to enable password checking and register services and users under the `Edit data` option.

The CLI takes these optional flags on startup:
- `--charset`, `-m <charset>` Define the characters to use in passwords that use the `Regular` scheme
- `--copy`, `-c` Copies the password into the clipboard for 15 seconds, instead of printing it into the console
- `--create-file <path>` A path to create a new data file at
- `--file`, `-f <path>` A path to a data file; data files allow for password checking and local account storage
- `--help`, `-h` Displays a help page
- `--import <path>` Specify a path to an exported file. You will be given the option to add the imported data to your data or replace it
- `--quick`, `-q` Skip most confirmation prompts
- `--show-password`, `-s` Repeatable; when used once, the master password is masked; when used twice, the password is shown; when omitted, the password is hidden
- `--timeout`, `-t <seconds>` Define an inactivity timeout after which to close the app; defaults to 120
- `--verbose`, `-v` Logs verbosely

This repository also includes an example data file (master password is 'password1'). Running `node . -f ./example` and answering `password1`, `Get passwords`, `example.com` and `admin` to the prompts will generate the password for `admin@example.com` with a salt of `abc`, as this salt was specified in the data file.

Finally, you can define a script to automatically launch evacora with the preferred flags. You can then execute this script from your desktop or another easily accessible place.
```
node /path/to/evacora -s -f /path/to/data.json -t 180
```

## How evacora works
evacora deterministically generates passwords from a master password along with the profile settings. The program flow looks like this:
![evacora flowchart](/../docs/docs/assets/flowchart.png)
The master password gets hashed using argon2id with a SHA-256 hash of the settings as salt at 20 iterations and 256 MiB RAM cost. The resulting hash then gets parsed into a unique password for every unique combination of profile settings and master password.<br/>
When you save local data, it is entirely encrypted with AES-256-GCM using a key derived from the master password.

## FAQ
- Q: Is this more secure than solutions maintaining state?
  - A: No. A properly implemented stateful solution encrypts any sensitive data, making it infeasible to steal data at rest. evacora is not inherently more secure than stateful solutions, it simply offers a level of independence not provided by other solutions.
- Q: What risks are there to be aware of while using evacora?
  - A: To enter the generated password into the service login, you will likely use the clipboard. Be aware that any running processes, focused browser tabs or browser plugins may read your clipboard and obtain passwords that way.
  - A: Clear your clipboard as soon as you paste the password, and disable clipboard history.
  - A: Try to harden yourself against keylogging attacks. Keyloggers may compromise your master password if you fall victim to one.
- Q: But I think stateless password management solutions are bad.
  - A: Ok. Don't use evacora then. This project is made and maintained by one person because they wanted a reliable stateless password manager for their personal use. The project is open source because others may find it useful, too. If you're not one of those people, feel free to use another password management solution.

## Choosing a naming and usage scheme
It is advised to start using a common naming and usage scheme early on to avoid guessing games on whether the service name was just `service`, `service.com` or `login.service.com`.<br/>
Which scheme to use is intentionally left at the discretion of the user, but an example scheme may be something like this:
- Only use the domainname (`example` instead of `example.com`) for services to allow for non-website based services
- Usernames are the full email (`user@web.mail`) or, if no email was used, the full username
- Salts are only used if a password is compromised. As salt, use the current year
- The default scheme to use is `Regular`, if the website rejects the password due to character restrictions, use `Alphanumeric with Special Character` instead
- If the generated password gets rejected because it is too long, go down to exactly 16 characters. If that is still too long, go down to 12

If these rules are enforced consistently, nearly all guessing games should be eliminated.
