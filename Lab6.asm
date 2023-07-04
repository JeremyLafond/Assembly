#Jeremy Lafond jalafond@ucsc.edu
#VIGENERE CIPHER
.data

.text
# Subroutine EncryptChar
# Encrypts a single character using a single key character.
# input: $a0 = ASCII character to encrypt
# $a1 = key ASCII character
# $t0 = holds value of ASCII input arg
# $s1 = flag for uppercase letter
# $t1 = holds value of ASCII key arg
# $t2 = holds sum of key and char
# $t3, $t4 = hold values of sums, differences and addition for overflow
# output: $v0 = Vigenere-encrypted ASCII character
# Side effects: None
# Notes: Plain and cipher will be in alphabet A-Z or a-z
# key will be in A-Z
#hex 41-5A = upper case
#hex 61-7A = lowercase
#65 #minimum value of capital letter
#90 #maximum value of capital letter 
#97 #minimum value of lowercase letter
#122 #max value of lowercase letter	
EncryptChar: nop
	sw $ra, ($sp) #store return address
	subi $sp, $sp, 4

	#load char
	#check for valid input ranges
	la $t0,($a0)
	blt $t0, 65, __NONLETT
	bgt $t0, 122, __NONLETT
	blt $t0, 97, __MAYSKIP
	b __KEYCHECK
	
	#check other end of range of char value
	__MAYSKIP:
		bgt $t0, 90, __NONLETT
		li $s1, 1 #flag for uppercase
		b __KEYCHECK
	
	#return non-letter to v0 unencrypted
	__NONLETT:
		move $v0, $t0
		b __RET
		
	#check key value ranges
	__KEYCHECK:
		#load key
		la $t1, ($a1)
		blt $t1, 65, __RET
		bgt $t1, 90, __MAYBERET
		bgt $t1, 122, __RET
		b __ENCRYPT
		
	#check key value deeper
	__MAYBERET:
		blt $t1, 97, __RET
		b __ENCRYPT
	 	
	#char and key are valid
	__ENCRYPT:
		beq $s1, 1, __UPPER
		beqz $s1, __LOWER
		
	#uppercase input
	__UPPER:
		#subtract 65 from key to get shift value
		sub $t1, $t1, 65
		#add key and char
		add $t2, $t1, $t0
		#wrap around exception if sum is too large
		bgt $t2, 90, __WRAPU
		move $v0, $t2
		b __RET
		
	#lowercase input
	__LOWER:
		#subtract 65 from key to get shift value
		sub $t1, $t1, 65
		#add key and char
		add $t2, $t1, $t0
		#wrap around exception if sum is too large
		bgt $t2, 122, __WRAPL
		move $v0, $t2
		b __RET
	
	#wrap around uppercase
	__WRAPU:
		#overflow sum - max val
		sub $t3, $t2, 90
		#diff + min upper val
		addi $t4, $t3, 64
		move $v0, $t4
		b __RET
		
	#wrap around lowercase
	__WRAPL:
		#overflow sum - max val
		sub $t3, $t2, 122
		#diff + min lower val
		addi $t4, $t3, 96
		move $v0, $t4
		b __RET
		
	#reset and return0
	 __RET:
	 	#return memory to previous state
	 	li $t0, 0
	 	li $t1, 0
	 	li $t2, 0
	 	li $t3, 0
	 	li $t4, 0
	 	li $s1, 0
	 	
	 	addi $sp, $sp, 4
		lw $ra, ($sp)
	 	jr $ra
	
# Subroutine DecryptChar
# Decrypts a single character using a single key character.
# input: $a0 = ASCII character to decrypt
# $a1 = key ASCII character
# $t0 = holds value of ASCII input arg
# $s1 = flag for uppercase letter
# $t1 = holds value of ASCII key arg
# $t2 = holds sum of key and char
# $t3, $t4 = hold values of sums, differences and addition for overflow
# output: $v0 = Vigenere-decrypted ASCII character
# Side effects: None
# Notes: Plain and cipher will be in alphabet A-Z or a-z
# key will be in A-Z
DecryptChar: nop
	sw $ra, ($sp) #store return address
	subi $sp, $sp, 4
	
	#load char
	#check input boundary
	la $t0,($a0)
	blt $t0, 65, __NONLETTD
	bgt $t0, 122, __NONLETTD
	blt $t0, 97, __MAYSKIPD
	b __KEYCHECKD
	
	#check other end of range of char value
	__MAYSKIPD:
		bgt $t0, 90, __NONLETTD
		li $s1, 1 #flag for uppercase
		b __KEYCHECKD
	
	#return non-letter to v0 unencrypted
	__NONLETTD:
		move $v0, $t0
		b __RETD
		
	#check key value and key boundary
	__KEYCHECKD:
		#load key
		la $t1, ($a1)
		blt $t1, 65, __RETD
		bgt $t1, 90, __MAYBERETD
		bgt $t1, 122, __RETD
		b __DECRYPT
		
	#check key value deeper
	__MAYBERETD:
		blt $t1, 97, __RETD
		b __DECRYPT
		
	#char and key are valid
	__DECRYPT:
		beq $s1, 1, __UPPERD
		beqz $s1, __LOWERD
	
	#uppercase wrap around	
	__UPPERD:
		#subtract 65 from key to get shift value
		sub $t1, $t1, 65
		#subtract char and key
		sub $t2, $t0, $t1
		#wrap around exception if diff is too small
		blt $t2, 65, __WRAPD
		move $v0, $t2
		b __RETD
		
	#lowercase wrap around
	__LOWERD:
		#subtract 65 from key to get shift value
		sub $t1, $t1, 65
		#subtract char and key
		sub $t2, $t0, $t1
		#wrap around exception if diff is too small
		blt $t2, 97, __WRAPD
		move $v0, $t2
		b __RETD
		
	#wrap around simpler than encrypt probably could have/should have done it this way
	__WRAPD:
		#max shift val + 1
		li $t3, 26
		#diff + min upper val
		add $v0, $t2, $t3
		b __RETD

	#reset and return
	 __RETD:
	 	#return memory to previous state
	 	li $t0, 0
	 	li $t1, 0
	 	li $t2, 0
	 	li $t3, 0
	 	li $s1, 0
	 	
	 	addi $sp, $sp, 4
		lw $ra, ($sp)
	 	jr $ra

# Subroutine EncryptString
# Encrypts a null-terminated string of length 30 or less,
# using a keystring.
# input: $a0 = Address of plaintext string
# $a1 = Address of key string
# $a2 = Address to store ciphertext string
# $s2 = holds value of ASCII input string
# $s3 = holds value of ASCII key arg string
# $t5 = holds value of ASCII input string for manipulation
# $t6 = holds value of ASCII key arg string for manipulation
# $t7, $t8, $t9 = hold values for various counters
# $v0 = holds value for encrypted ASCII char after encryption
# output: None
# Side effects: String at $a2 will be changed to the
# Vigenere-encrypted ciphertext.
# $a0, $a1, and $a2 may be altered
EncryptString: nop
	sw $ra, ($sp) #store return address
	subi $sp, $sp, 4
	
	#load a0 and a1 strings respectively for later
	la $s2, ($a0)
	la $s3, ($a1)
	#store strings into temps for manipulation
	la $t5, ($s2)
	la $t6, ($s3)
	#initialize some counters for use later
	#initialize a0 a1 to 0
	li $t9, 0
	li $t8, 0
	li $t7, 0
	li $a0, 0
	li $a1, 0
	
	__LOOPE:
		#shave byte off temp string into a0 and a1 as char sized args
		lb $a0, ($t5)
		lb $a1, ($t6)
		#check for key wrap around or illegal char
		beqz, $a1, __KEYLOOPE
		blt $a1, 65, __KEYINCE
		bgt $a1, 90, __KEYINCE
		#encrypt char size arg
		jal EncryptChar
		#move value from v0 into an array
		sb $v0, testES_result($t7)
		#check for end of input to exit
		beqz, $v0, __EXITE
		#increment
		addi $t5, $t5, 1
		addi $t7, $t7, 1
		addi $t9, $t9, 1
		#check for max size
		bgt $t9, 29, __EXITE
		#check for non-letter
		bgt $v0, 122, __LOOPE
		blt $v0, 41, __LOOPE
		bgt $v0, 90, __CHECK2
		b __KEYINCE
	
	#check deeper for non-letter
	__CHECK2:
		blt $v0, 96, __LOOPE
		b __KEYINCE
	
	#key case if non-cap		
	__KEYINCE:
		addi $t6, $t6, 1
		addi $t8, $t8, 1
		b __LOOPE
		
	#key wrap around
	__KEYLOOPE:
		sub $t6, $t6, $t8
		li $t8, 0
		b __LOOPE
	#exit	
	__EXITE:
		#put old strings back into args
		move $a0, $s2
		move $a1, $s3
		#store null terminator
		sb $0, testES_result($t7)
		#store entire string into data array
		la $t2, testES_result
		#put entire string into a2 arg
		move $a2, $t2
		#reset memory
		li $t2, 0
		li $t5, 0
		li $t6, 0
		li $t7, 0
		li $t8, 0
		li $s2, 0
		li $s3, 0
		
		addi $sp, $sp, 4
		lw $ra, ($sp)
		jr $ra
		
# Subroutine DecryptString
# Decrypts a null-terminated string of length 30 or less,
# using a keystring.
# input: $a0 = Address of ciphertext string
# $a1 = Address of key string
# $a2 = Address to store plaintext string
# $s2 = holds value of ASCII input string
# $s3 = holds value of ASCII key arg string
# $t5 = holds value of ASCII input string for manipulation
# $t6 = holds value of ASCII key arg string for manipulation
# $t7, $t8, $t9 = hold values for various counters
# $v0 = holds value for decrypted ASCII char after decryption
# output: None
# Side effects: String at $a2 will be changed to the
# Vigenere-decrypted plaintext
# $a0, $a1, and $a2 may be altered
DecryptString: nop
	sw $ra, ($sp) #store return address
	subi $sp, $sp, 4

	#load a0 and a1 strings respectively for later
	la $s2, ($a0)
	la $s3, ($a1)
	#store strings into temps for manipulation
	la $t5, ($s2)
	la $t6, ($s3)
	#initialize counters for later use
	li $t9, 0
	li $t8, 0
	li $t7, 0
	li $a0, 0
	li $a1, 0
	
	__LOOPD:
		#shave byte off temp string into a0 and a1 as char sized args
		lb $a0, ($t5)
		lb $a1, ($t6)
		#check for key wrap around or illegal char
		beqz, $a1, __KEYLOOPD
		blt $a1, 65, __KEYINCD
		bgt $a1, 90, __KEYINCD
		#decrypt char size arg
		jal DecryptChar
		#move value from v0 into an array
		sb $v0, testDS_result($t7)
		#check for end of input to exit
		beqz, $v0, __EXITD
		#increment
		addi $t5, $t5, 1
		addi $t7, $t7, 1
		addi $t9, $t9, 1
		#maxStrLen = 31 but looping starts at 30 check for size
		bgt $t9, 29, __EXITD
		#check for non-letter
		bgt $v0, 122, __LOOPD
		blt $v0, 41, __LOOPD
		bgt $v0, 90, __CHECKD
		b __KEYINCD
	
	#check deeper for non-letter
	__CHECKD:
		blt $v0, 96, __LOOPD
		b __KEYINCD
	
	#key case if non-cap
	__KEYINCD:
		addi $t6, $t6, 1
		addi $t8, $t8, 1
		b __LOOPD
	
	#key wrap around
	__KEYLOOPD:
		sub $t6, $t6, $t8
		li $t8, 0
		b __LOOPD
		
	#exit	
	__EXITD:
		move $a0, $s2
		move $a1, $s3
		sb $0, testDS_result($t7)
		la $t2, testDS_result
		move $a2, $t2
		#reset memory
		li $t2, 0
		li $t3, 0
		li $t4, 0
		li $t5, 0
		li $t6, 0
		li $t7, 0
		li $t8, 0
		li $t9, 0
		li $s2, 0
		li $s3, 0
			
		addi $sp, $sp, 4
		lw $ra, ($sp)
		jr $ra
