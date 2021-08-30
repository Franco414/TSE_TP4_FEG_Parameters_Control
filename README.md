# Development of Parameters Control with Ceedling (TDD)

**Autor:** Gerónimo, Franco Ezequiel

Specialization in Embedded Systems, (FIUBA)
## Steps list to run the code

a) You must open a console and go to the project folder.

b) Type and run "**ceedling**" command.

## Description the project

ModuleTp4 is a module to load different access parameters to establish the connection to the remote VPN network. To enter a data, it must be loaded character by character to an FSM, where it will be processed to determine if it is a valid parameter.

This code has been developed with the TDD methodology, it consists of executing the following cycle. Firstly the tests are developed, then the minimum essential code is implemented to solve the tests and finally improvements are made to the program.

Opaque pointers were also used to restrict access to the main structure of the system, which contains the setting of the present application, as well as the access parameters. the latter being the only elements of the structure accessible through public methods. Each function can return the current value based on the memory address of the private structure.

Implementation of opaque pointer.

```C
typedef struct tpData_s* tpData_t;
```

### Input Format

```
  Init     +  Data Type   +  Identifier  + Parameter  +  Parameter  +  Parameter
Character     Identifier      Finish         Start                      Finish
                             Character     Character                   Character
```

1. **Init Character**: Character employed to indicate the start of a new command. Its _Update value_ is : **<**

2. **Data Type Identifier**: It is an array of characters used to indicate to the system the type of parameter to receive. This data field can take three different values. They are **IP**, **User**, **Pass**.

3. **Identifier Finish Character**: Character employed to indicate the end of the data type identifier field, so that the system verifies that It is valid. Its _update value_ is: **:**

4. **Parameter Start Character**: Character used to indicate to the system that it will begin to receive the parameter. Its _update value_ is: **"**

5. **Parameter**: It is an array of characters that stores the access parameter to the remote VPN network.

6. **Parameter Finish Character**: Character employed to indicate to the system the end of the parameter and therefore of the command. Its _update value_ is: **"**

#### Examples

- <IP:"10.0.0.1"
- <User:"username"
- <Pass:"ab12CD@w"

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
