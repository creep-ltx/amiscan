// Package rardecode reads RAR archives (formats 1.5 to 7). It is
// github.com/nwaples/rardecode/v2 v2.2.3 by Nicholas Waples (BSD 2-clause
// licence, see LICENSE), copied into BBX with these fixes (marked "BBX
// patch"), checked byte for byte against unrar on 1990s BBS archives:
//
//   - decodeReader.copyBytes dropped the part of a match that ran past the
//     end of the window, so everything after the window first wrapped came
//     out wrong (seen in solid RAR 2.x archives, whose window is small).
//   - RAR 2.0: the multimedia (audio) decoder read the delta and the
//     channel delta as unsigned where unrar uses signed bytes.
//   - RAR 2.0: tables stored at the end of a file, or in an empty file, for
//     the next file of a solid archive were not read (unrar's
//     ReadLastTables), so that next file came out wrong.
//   - RAR 2.0: a match running past a file's end left the size negative
//     and the decoder returned nothing, for ever; and any decoder that
//     keeps returning nothing now stops with an error.
//
// Go back to the upstream module once it has these fixes.
package rardecode
