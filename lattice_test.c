#include <stdio.h>

typedef long long ll;

ll extended_gcd(ll a, ll b, ll *x, ll *y)
{
    if (a == 0)
    {
        *x = 0;
        *y = 1;
        return b;
    }

    ll _x, _y;
    ll gcd = extended_gcd(b % a, a, &_x, &_y);

    *x = _y - (b/a) * _x;
    *y = _x;

    return gcd;
}

int main() {
    ll q = 122430513841, h = 39245579300;
    for (ll g = 174950; g < 247417; g++){
        ll x, y;
        extended_gcd(h, q, &x, &y);
        ll f = (x * g) % q;
        if (f < 247417) {
            printf("f = %lld, g = %lld\n", f, g);
        }
    }
    return 0;
}
