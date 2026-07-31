# Unambiguous encoding

Following Sec 2.6 in the [CGGMP24 specification](https://lfdt-lockness.github.io/cggmp21/cggmp24-spec.pdf), we define an encoding function that avoids collision caused by ambiguity in concatenation, such as `"ab" || "c"` vs `"a" || "bc"`.  Specifically, `encode()` satisifes three properties:
- Injectivity
- Platform independence

## Functions

- Little-endian ordering for the byte string of a 64-bit unsigned integer $x$ is defined as $\mathsf{le64}(x)$.

## Encoding

$\text{Encode}(x_1, \cdots, x_n)\rightarrow y$

Input
- byte strings $x_1, \cdots, x_n$

Output: byte string $y$
- $y \leftarrow \mathsf{le64}(|x_1|) \parallel x_1 \parallel \cdots \parallel \mathsf{le64}(|x_n|) \parallel x_n$



