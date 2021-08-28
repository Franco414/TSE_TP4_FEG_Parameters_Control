# Development of Parameters Control with Ceedling (TDD)

**Autor:** Gerónimo, Franco Ezequiel

Specialization in Embedded Systems, (FIUBA)
## Steps list to run the code

a) You must open a console and go to the project folder.

b) Type and run "**ceedling**" command.

## Description the project

ModuleTp4 is a module to loading different access parameters to establish the connection with the remote VPN network.

To enter a data, it must be loaded character by character to an FSM, where it will be processed to determine if it is a valid parameter.

Implementation of opaque pointer.


```C
typedef struct tpData_s* tpData_t;
```


**Access parameters**:

* Public IP address.
* VPN user.
* VPN password.

### Specifications to determining a valid IP address:

1. Each element of IP address is a number from 0 to 9 expressed in ASCII or a period separator character '.'
2. It has 4 data fields separated by points characters '.'
3. Each data field has a maximum of three digits.
4. There aren't any empty data field.

### Specifications to determining a valid VPN user:

1. It has a minimum of six characters.
2. It has a maximum of twelve characters.
3. A null or empty username is not accepted.

### Specifications to determining a valid VPN pass:

1. It has a minimum of eight characters.
2. It has a maximum of twelve characters.
3. Each IP address has at least one capital letter.
4. Every IP address has at least one lowercase letter.
5. Each IP address has at least one number.
6. It has at least one special character.