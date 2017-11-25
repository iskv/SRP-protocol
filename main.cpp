#include <QCoreApplication>
#include <QCryptographicHash>
#include <QString>

#include <iostream>

#include "BigIntegerLibrary.hh"

using namespace std;

QString hash_sha1(QString s);
QString hash_sha1(QString s1, QString s2);
QString hash_sha1(QString s1, QString s2, QString s3);

QString xor_f(QString s1, QString s2);
QString gen_sole(int n);

BigUnsigned pow_u(BigUnsigned b, BigUnsigned i);

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

try {

    QString N = "c037c37588b4329887e61c2da332"
                "4b1ba4b81a63f9748fed2d8a410c2f"
                "c21b1232f0d3bfa024276cfd884481"
                "97aae486a63bfca7b8bf7754dfb327"
                "c7201f6fd17fd7fd74158bd31ce772"
                "c9f5f8ab584548a99a759b5a2c0532"
                "162b7b6218e8f142bce2c30d778468"
                "9a483e095e701618437913a8c39c3d"
                "d0d4ca3c500b885fe3";

    QString g = "2";
    QString k = "3";

    cout << "N, g, and k are known beforehand to both client and server:\n";

    cout << "N=" << N.toStdString() << "\n"
         << "g=" << g.toStdString() << "\n"
         << "k=" << k.toStdString() << endl;

    cout << "0. server stores (I, s, v) in its password database:\n";

    QString I = "person";
    QString p = "password1234";
    QString s = gen_sole(8);
    QString x = hash_sha1(s,I,p);
    BigUnsigned x_t = BigUnsignedInABase(x.toStdString(),16);
    BigUnsigned N_t = BigUnsignedInABase(N.toStdString(),16);
    BigUnsigned g_t = BigUnsignedInABase(g.toStdString(),16);
    BigUnsigned v = modexp(g_t,x_t,N_t);

    cout << "I=" << I.toStdString() << "\n"
         << "p=" << p.toStdString() << "\n"
         << "s=" << s.toStdString() << "\n"
         << "x=" << x.toStdString() << "\n"
         << "v=" << v << endl;

    cout << "1. client sends username I and public ephemeral value A to the server\n";

    BigUnsigned a_rand = BigUnsignedInABase((QString().setNum(qrand())).toStdString(),16);
    BigUnsigned A = modexp(g_t,a_rand,N_t);

    cout << "a=" << a_rand << "\n"
         << "A=" << A << endl;

    cout << "2. server sends user's salt s and public ephemeral value B to client\n";

    BigUnsigned b_rand = BigUnsignedInABase((QString().setNum(qrand())).toStdString(),16);
    BigUnsigned k_t = BigUnsignedInABase(k.toStdString(),16);
    BigUnsigned B = ( k_t * v + modexp(g_t,b_rand,N_t) ) % N_t;

    cout << "b=" << b_rand << "\n"
         << "B=" << B << endl;

    cout << "3. client and server calculate the random scrambling parameter\n";

    QString u = hash_sha1(QString().fromStdString(bigUnsignedToString(A)),QString().fromStdString(bigUnsignedToString(B)));

    cout << "u=" << u.toStdString() << "\n";

    cout << "4. client computes session key\n";

    //x = hash_sha1(s,I,p);
    //x_t = BigUnsignedInABase(x.toStdString(),16);
    BigUnsigned u_t = BigUnsignedInABase(u.toStdString(),16);

    BigUnsigned p1 = k_t * modexp(g_t,x_t,N_t);
    BigInteger p2 = BigInteger(B) - BigInteger(p1);
    BigUnsigned p3 = a_rand + u_t * x_t;
    BigUnsigned S_c = modexp(p2,p3,N_t);
    QString K_c = hash_sha1(QString().fromStdString(bigUnsignedToString(S_c)));

    cout << "S_c=" << S_c << "\n"
         << "K_c=" << K_c.toStdString() << "\n";

    cout << "5. server computes session key\n";

    p1 = A * modexp(v,u_t,N_t);
    BigUnsigned S_s = modexp(p1,b_rand,N_t);
    QString K_s = hash_sha1(QString().fromStdString(bigUnsignedToString(S_s)));

    cout << "S_s=" << S_s << "\n"
         << "K_s=" << K_s.toStdString() << "\n";

    cout << "6. client sends proof of session key to server\n";

    QString M_c = hash_sha1(xor_f(hash_sha1(N),hash_sha1(g)),s + QString().fromStdString(bigUnsignedToString(A)) + QString().fromStdString(bigUnsignedToString(B)) + K_c);

    cout << "M_c=" << M_c.toStdString() << "\n";

    cout << "7. server sends proof of session key to client\n";

    QString M_s = hash_sha1(QString().fromStdString(bigUnsignedToString(A)),M_c,K_s);

    cout << "M_s=" << M_s.toStdString() << "\n";

} catch (char* err) {
        cout << err << endl;
    }

    return a.exec();
}

QString hash_sha1(QString s)
{
    return QString(QCryptographicHash::hash(s.toUtf8(),QCryptographicHash::Sha1).toHex());
}

QString hash_sha1(QString s1, QString s2)
{
    return hash_sha1(s1 + s2);
}

QString hash_sha1(QString s1, QString s2, QString s3)
{
    return hash_sha1(s1 + s2 + s3);
}

QString xor_f(QString s1, QString s2)
{
    QString res;
    for (int i = 0; i < s1.size(); i++)
        res.push_back(s1[i].cell()^s2[i].cell());
    return res;
}

QString gen_sole(int n)
{
    QString res;
    for ( int i = 0 ; i < n; i++)
        res.push_back(qrand());
    return res;
}
