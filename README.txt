Jeremy Lafond jalafond@ucsc.edu
VIGENERE CIPHER

Psuedo
**********************************************************************************************
EncryptChar:
read key, store to temp from a1
read memory to access value of char 
handle exceptions involving ignored chars
(flag for skip out to next char, return memory to previous state)

read char
store to temp from a0
read memory to access value of key
handle exceptions involving lowercase/ignored chars
(flag for skip out to next char, return memory to previous statE)

edit stored memory of char by adding value of key to it.
handle wrap around exception so that if char + key > 25 then char = key - (MAX_VAL - char)
return this new char value in v0
reset modified memory values


DecryptChar:
read key, store to temp from a1
read memory to access value of char 
handle exceptions involving ignored chars
(flag for skip out to next char, return memory to previous state)

read char
store to temp from a0
read memory to access value of key
handle exceptions involving lowercase/ignored chars
(flag for skip out to next char, return memory to previous statE)

edit stored memory of char by subtracting value of key from it.
handle wrap around exception so that if char - key < 0 then char = (char - key) + MAX_VAL
return this new char value in v0
reset modified memory values


EncryptString:
handle exception for string of more than 30
write text input to a0
write key input to a1
loop: terminating at final address of a0(null):
		call EncryptChar:
		take index of a0 as char and index of a1 as key
		handle exception where index of key < index of text 
		(reset value of key index to 0 to pull first address of a1)
		keep in mind memory stores based on value not order
		store v0 from EncryptChar: to a2
		++ a0, a1, a2
		b loop

DecryptString:
handle exception for string of more than 30
write text input to a0
write key input to a1
loop: terminating at final address of a0(null):
		call DecryptChar:
		take index of a0 as char and index of a1 as key
		handle exception where index of key < index of text 
		(reset value of key index to 0 to pull first address of a1)
		keep in mind memory stores based on value not order
		store v0 from DecryptChar: to a2
		++ a0, a1, a2
		b loop
(basically the same but calls DecryptChar)

Possible issues: 
-Order of chars stored in memory
-accessing and modifying memory address by address
-retaining ignored characters in final decrypted and intermediated encrypted output???
**********************************************************************************************
Psuedo 2nd pass
**********************************************************************************************
EncryptChar:
	check char:
	la into temp from arg
	blt values below 65
	bgt values above 122
	blt values below min lowercase
	b check key

		for vals below min lowercase:
			check if greater than max uppercase
			flag if true
			else check key

		for vals below or above alphabet:
			move value directly into vo
			reset modified values
			return

		check key:
			la into temp from arg
			blt values below 65
			bgt values above 122
			b encrypt

		for vals below 65 or above 122:
		reset modified values
		return

	encrypt:
		if flag is true:
		uppercase
		if flag is false:
		lowercase

	uppercase:
		sub 65 from key value to get shift value (0-25)
		add key and char
		if sum > 90 deal with wrap around
		else
		move sum to v0
		reset values
		return

	lowercase:
		same as uppercase but sum must be below 122 and is sent to diff wrap around

	wrap upper:
		take overflowed sum and subtract maximum uppercase val from it(90)
		add that result to the minimum uppercase value (65)
		store in v0
		reset values
		return

	wrap lower:
		deal with it the same way as uppercase but max is 122 min is 97

DecryptChar:
	deal with most things similarly
	except for uppercase: and lowercase:

	upper case d:
		subtract 65 to get shift value
		subtract char and key
		if difference is less than 65 deal with wraparound
		else
		move difference to v0
		reset values
		return

	lower case d:
		same as upper case d except difference would be less than 97

	wrap uppercase d:
		take difference and add it to max shift value + 1
		store value in v0
		reset values
		return

	wrap uppercase d:
		same exact ? maybe i overcomplicated my cases in encrypt?
