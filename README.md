# meltdown
My very simple meltdown implementation. It doesn't require TSX extension thus works on old Intel CPUs.

By default it guesses byte value from local not protected address and works even on patched OS.

Guessing values form global addresses works only on not patched OS.

Guessing not always succeeds. Very often you have to run the program few times to see the result.
