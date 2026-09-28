# WebSECRobot düzeltme istemi

Canlı rapordaki “Düzeltme istemini kopyala” eylemi, kritik/yüksek/orta bulguları kod ajanına aktarır. İstem özellikle şunları zorunlu tutar:

- yalnızca yetkili projede çalışma;
- ilgisiz kullanıcı değişikliklerini koruma;
- CSP, CORS ve çerezleri körlemesine değiştirmeme;
- canlı HTTP davranışıyla doğrulama;
- exploit, parola denemesi ve veri çıkarma yapmama;
- uydurma güvenlik iletişim adresi üretmeme.
