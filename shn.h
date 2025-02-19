/* $Id: $ */
/* Shannon: Shannon stream cipher and MAC header files */

/*
THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE AND AGAINST
INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _SHN_DEFINED
#define _SHN_DEFINED 1

#include <limits.h>
#include <stdint.h>

#define SHN_WORDS 16
typedef unsigned char UCHAR;
typedef uint32_t WORD;

#define ROTL(w, x) (((w) << (x)) | ((w) >> (32 - (x))))
#define ROTR(w, x) (((w) >> (x)) | ((w) << (32 - (x))))

typedef struct {
	WORD R[SHN_WORDS];     /* Working storage for the shift register */
	WORD CRC[SHN_WORDS];   /* Working storage for CRC accumulation */
	WORD initR[SHN_WORDS]; /* saved register contents */
	WORD konst;            /* key dependent semi-constant */
	WORD sbuf;             /* encryption buffer */
	WORD mbuf;             /* partial word MAC buffer */
	int nbuf;              /* number of part-word stream bits buffered */
} shn_ctx;

/* interface definitions */
void shn_key(shn_ctx *c, const UCHAR key[], int keylen);    /* set key */
void shn_nonce(shn_ctx *c, const UCHAR nonce[], int nlen);  /* set Init Vector */
void shn_stream(shn_ctx *c, UCHAR *buf, int nbytes);        /* stream cipher */
void shn_maconly(shn_ctx *c, const UCHAR *buf, int nbytes); /* accumulate MAC */
void shn_encrypt(shn_ctx *c, UCHAR *buf, int nbytes);       /* encrypt + MAC */
void shn_decrypt(shn_ctx *c, UCHAR *buf, int nbytes);       /* decrypt + MAC */
void shn_finish(shn_ctx *c, UCHAR *buf, int nbytes);        /* finalise MAC */

#endif /* _SHN_DEFINED */
