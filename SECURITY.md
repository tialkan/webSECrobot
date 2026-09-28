# Güvenlik politikası

WebSECRobot'ta bulduğunuz güvenlik açığını herkese açık issue olarak paylaşmayın. Depo sahibine GitHub Security Advisory üzerinden özel bildirim gönderin.

## Yetkili kullanım

Aracı yalnızca sahibi olduğunuz veya denetlemek için açık izin aldığınız sistemlerde kullanın. WebSECRobot pasif kalacak şekilde tasarlanmıştır: normal `GET` istekleri ve zararsız bir `Origin` başlığı dışında saldırı yükü göndermez; port taramaz, parola denemez ve açık istismar etmez.

## Sunucu tarafı istek güvenliği

- Yalnızca HTTP(S) ve 80/443 portları kabul edilir.
- Yerel, özel, loopback, bağlantı-yerel ve ayrılmış IP aralıkları reddedilir.
- Her yönlendirme hedefi yeniden doğrulanır.
- İstek süresi, yanıt boyutu, yönlendirme ve sayfa sayısı sınırlıdır.

DNS denetimi tek başına kusursuz bir ağ sınırı değildir. Herkese açık kurulumlarda bulut metadata ve iç ağ erişimini egress firewall/proxy ile ayrıca engelleyin, oran sınırlama uygulayın ve süreci ayrıcalıksız çalıştırın.
