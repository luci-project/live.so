#include "fib.h"

const unsigned short version = 6;

static const unsigned long lookup[] = {
	0UL, 1UL, 1UL, 2UL, 3UL, 5UL, 8UL, 13UL, 21UL, 34UL, 55UL, 89UL, 144UL,
	233UL, 377UL, 610UL, 987UL, 1597UL, 2584UL, 4181UL, 6765UL, 10946UL,
	17711UL, 28657UL, 46368UL, 75025UL, 121393UL, 196418UL, 317811UL, 514229UL,
	832040UL, 1346269UL, 2178309UL, 3524578UL, 5702887UL, 9227465UL, 14930352UL,
	24157817UL, 39088169UL, 63245986UL, 102334155UL, 165580141UL, 267914296UL,
	433494437UL, 701408733UL, 1134903170UL, 1836311903UL, 2971215073UL,
	4807526976UL, 7778742049UL, 12586269025UL, 20365011074UL, 32951280099UL,
	53316291173UL, 86267571272UL, 139583862445UL, 225851433717UL,
	365435296162UL, 591286729879UL, 956722026041UL, 1548008755920UL,
	2504730781961UL, 4052739537881UL, 6557470319842UL, 10610209857723UL,
	17167680177565UL, 27777890035288UL, 44945570212853UL, 72723460248141UL,
	117669030460994UL, 190392490709135UL, 308061521170129UL, 498454011879264UL,
	806515533049393UL, 1304969544928657UL, 2111485077978050UL,
	3416454622906707UL, 5527939700884757UL, 8944394323791464UL,
	14472334024676221UL, 23416728348467685UL, 37889062373143906UL,
	61305790721611591UL, 99194853094755497UL, 160500643816367088UL,
	259695496911122585UL, 420196140727489673UL, 679891637638612258UL,
	1100087778366101931UL, 1779979416004714189UL, 2880067194370816120UL,
	4660046610375530309UL, 7540113804746346429UL, 12200160415121876738UL
};

unsigned long fib(unsigned long value) {
	return value < sizeof(lookup)/sizeof(lookup[0]) ? lookup[value] : 0;
}

int print_library_info(FILE *stream) {
	return fprintf(stream, "[using Fibonacci library v%u: O(1)]\n", version);
}
