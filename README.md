# evacora
evacora is a stateless password manager. It calculates passwords on the fly, using the information you provide along with your master password. Your passwords are never stored anywhere. Because passwords are never stored you also don't need to sync them, meaning you don't have to send them to a cloud server, and don't have to sync files between devices.

## How to use evacora
You can use evacora by running the CLI with nodeJS or by using the [web version](https://mahakadema.github.io/evacora). The CLI runs faster and allows for local storage of accounts and password checking for your master password.

To generate a password, enter a service name and master password. A username can be used to manage multiple accounts. A salt can be specified to change the generated password, which can be used for password resets.

To use the CLI, download the latest release zip, unzip the file and run `node .` inside the directory.

## Using the CLI
The CLI takes certain additional options on startup:
- `--help`, `-h` Displays a help page
- `--file`, `-f <path>` A path to a data file (see below)
- `--charset`, `-m <charset>` Define up to 64 characters to be used in the password, intended to circumvent character restrictions.
- `--verbose`, `-v` Logs verbosely
- `--copy`, `-c` Copies the password into the clipboard for 15 seconds, instead of printing it into the console

The `--file` option may point towards a JSON file containing information on registered accounts as well as a checksum for the master password. An `example.json` file can be found in this repository. By default, the option points to `./.json`.
If the supplied username matches any of the aliases of the registered accounts for the service, the full name of the account is automatically selected.
If a valid file is found, the service name and user options have all options listed. Additionally, if the selected user has a salt and length defined, the CLI will not ask for them.
If a valid file is found, the master password is matches against the `checksum` property if present. `checksum` should contain an `argon2id` hash of the password. If `checksum` is set to `"null"`, password checks are disabled and evacora will start to output an argon2id hash to be set as the value of `checksum`.

For example, running `node . -f ./example.json` and answering `example.com`, `admin` and `password1` to the prompt will generate the 45 character password for the `admin@example.com` account with a salt of `abc`.

You can also define a script to automatically launch evacora with the preferred flags. You can then execute this script from your desktop or another easily accessible place.
```
node /path/to/evacora -f /path/to/data.json
```

## No storage does not mean zero risk
Just because evacora does not require you to store your passwords anywhere does not mean you cannot have your passwords stolen. You will most likely copy the password to your clipboard to log into the service. Therefore any application able to read your clipboard may read out the passwords. An open website may read your clipboard if you focus the tab, any browser extentions may read your clipboard and any application running on your machine with sufficient permissions may read your keystrokes, allowing it to even read out your master password. It is therefore advised to never use evacora on machines you do not trust, to clear the clipboard after you logged in (and to disable clipboard history), and to make sure you trust your browser addons.
