---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Test-DDDnsPropagation
## SYNOPSIS
Checks how DNS records propagate across public resolvers.

## SYNTAX
### Builtin (Default)
```powershell
Test-DDDnsPropagation [-DomainName] <string[]> [-RecordType] <DnsRecordType> [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <Int32>] [-MaxParallelism <Int32>] [-DnsParallelism <Int32>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <Int32>] [-Country <CountryId>] [-Location <LocationId>] [-Take <Int32>] [-CountryCount <hashtable>] [-CompareResults] [-AsView] [-MaxResultsToKeep <int>] [-SnapshotPath <string>] [-Diff] [<CommonParameters>]
```

### ServersFile
```powershell
Test-DDDnsPropagation [-DomainName] <string[]> [-RecordType] <DnsRecordType> [-ServersFile] <string> [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <Int32>] [-MaxParallelism <Int32>] [-DnsParallelism <Int32>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <Int32>] [-Country <CountryId>] [-Location <LocationId>] [-Take <Int32>] [-CountryCount <hashtable>] [-CompareResults] [-AsView] [-MaxResultsToKeep <int>] [-SnapshotPath <string>] [-Diff] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
$file = Join-Path (Split-Path ([System.Reflection.Assembly]::GetExecutingAssembly().Location)) 'Data/DNS/PublicDNS.json'; Test-DDDnsPropagation -DomainName example.com -RecordType A -ServersFile $file
```


### EXAMPLE 2
```powershell
Test-DDDnsPropagation -DomainName example.com -RecordType A -CountryCount @{PL=3;DE=2}
```


## PARAMETERS

### -ArtifactsDirectory
Destination directory for artifacts when emitted.

```yaml
Type: String
Parameter Sets: Builtin, ServersFile
Aliases: ArtifactsPath
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsView
Return a typed view object suitable for composition reports.

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CompareResults
Return aggregated comparison of results.

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Country
Filter servers by country.

```yaml
Type: CountryId
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values: Afghanistan, Albania, Algeria, AmericanSamoa, Andorra, Angola, Antarctica, AntiguaAndBarbuda, Argentina, Armenia, Aruba, Australia, Austria, Azerbaijan, Bahamas, Bahrain, Bangladesh, Barbados, Belarus, Belgium, Belize, Benin, Bermuda, Bhutan, BoliviaPlurinationalStateOf, BonaireSintEustatiusAndSaba, BosniaAndHerzegovina, Botswana, Brazil, BruneiDarussalam, Bulgaria, BurkinaFaso, Burundi, Cambodia, Cameroon, Canada, CapeVerde, CaymanIslands, Chad, Chile, China, Colombia, Congo, CongoTheDemocraticRepublicOfThe, CostaRica, Croatia, Cuba, Cyprus, CzechRepublic, CôteDIvoire, Denmark, DominicanRepublic, Ecuador, Egypt, ElSalvador, EquatorialGuinea, Estonia, Ethiopia, Finland, France, FrenchGuiana, FrenchPolynesia, Gabon, Georgia, Germany, Ghana, Gibraltar, Greece, Greenland, Guadeloupe, Guam, Guatemala, Guernsey, Guinea, Honduras, HongKong, Hungary, Iceland, India, Indonesia, IranIslamicRepublicOf, Iraq, Ireland, IsleOfMan, Israel, Italy, Jamaica, Japan, Jersey, Jordan, Kazakhstan, Kenya, KoreaRepublicOf, Kuwait, Kyrgyzstan, LaoPeopleSDemocraticRepublic, Latvia, Lebanon, Liberia, Libya, Liechtenstein, Lithuania, Luxembourg, Macao, MacedoniaRepublicOf, Madagascar, Malawi, Malaysia, Maldives, Mali, Malta, MarshallIslands, Martinique, Mauritania, Mauritius, Mayotte, Mexico, MoldovaRepublicOf, Monaco, Mongolia, Montenegro, Morocco, Mozambique, Myanmar, Namibia, Nepal, Netherlands, NewCaledonia, NewZealand, Nicaragua, Niger, Nigeria, Norway, Oman, Pakistan, Palau, PalestineStateOf, Panama, PapuaNewGuinea, Paraguay, Peru, Philippines, Poland, Portugal, PuertoRico, Qatar, Romania, RussianFederation, Rwanda, Réunion, SaintVincentAndTheGrenadines, SaudiArabia, Senegal, Serbia, Seychelles, SierraLeone, Singapore, Slovakia, Slovenia, SolomonIslands, Somalia, SouthAfrica, Spain, SriLanka, Sudan, Swaziland, Sweden, Switzerland, SyrianArabRepublic, TaiwanProvinceOfChina, Tajikistan, TanzaniaUnitedRepublicOf, Thailand, TimorLeste, Togo, TrinidadAndTobago, Tunisia, Turkey, Uganda, Ukraine, UnitedArabEmirates, UnitedKingdom, UnitedStates, Uruguay, Uzbekistan, VenezuelaBolivarianRepublicOf, VietNam, VirginIslandsUS, XK, Yemen, Zambia, Zimbabwe, ÅlandIslands

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CountryCount
Select number of servers per country.

```yaml
Type: Hashtable
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Diff
Return changes since last snapshot.

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableParallel
Disable parallel execution for cmdlet-level work.

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoints
Optional list of resolver endpoints to use (multi-resolver).

```yaml
Type: DnsEndpoint[]
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsParallelism
DNS resolver concurrency hint for health checks.

```yaml
Type: Int32
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Domain(s) to query.

```yaml
Type: String[]
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportArtifacts
Emit artifacts (scan.json, metrics.json, progress.jsonl).

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: Artifacts
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportFormat
Desired export format(s). Accepts one or many values.

```yaml
Type: ReportFormat[]
Parameter Sets: Builtin, ServersFile
Aliases: Report
Possible values: Html, Json, Word, Excel, Markdown, MarkdownHtml

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportPath
Output file path for export.

```yaml
Type: String
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Location
Filter servers by location.

```yaml
Type: LocationId
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values: Aalborg, Aalst, Aarhus, Abeokuta, Abidjan, AblonSurSeine, Abomey, AbuDhabi, Abuja, Accra, Achinsk, Acre, Adamantina, Adapazarı, AddisAbaba, Adelaide, Aden, Adnet, Adony, Agege, Agfalva, Aguada, AguasBuenas, Aguascalientes, Ahmedabad, Ahuachapan, Aigaleo, Aigle, AinMerane, Ajman, Aktau, Aktobe, AlAinCity, AlBayda, AlFujairahCity, AlLith, AlMuharraq, AlQabil, AlQahirahAlJadidah, AlQatif, AlQuoz, AlYarmuk, Alajuela, Alanya, AlbaIulia, Alberton, AlbertslundMunicipality, AlcaláDeHenares, Alcobendas, AleksandrówŁódzki, Aleksinac, Alexandria, Alexandroupoli, Alghero, Algiers, Algodonales, Algueirao, Alicante, Alingsas, Alkmaar, Allens, Allingabro, Almada, Almaty, AlorGajah, Aloran, Alta, Altamura, Altdorf, AlvaroObregon, Alytus, Amadora, Amaliada, Amara, Ambah, Ambato, Amberley, America, Amman, Amstelveen, Amsterdam, Anadia, Ancona, Andalsnes, Andalusia, AndorraLaVella, Andover, Anduring, AneniiNoi, AngaurState, AngelesCity, Angol, Anjo, Ankara, Annaba, Antakya, Antananarivo, AntiguoCuscatlan, Antwerp, Apizaco, Apodaca, ArAra, ArRifa, Aracariguama, Aracuai, Arad, Arafat, Ararat, Ardalstangen, Areannamkwaengi, Aregua, Arendal, Arequipa, Arezzo, Argelato, Argilly, Argyroupoli, Arica, Arklow, Arneberg, Arnhem, Arusha, Arvika, Aryanah, AsSalimiyah, Asaba, Ashdod, Ashquelon, Asilah, Astana, Asunción, Asuwa, Atakum, Athens, Atherstone, Athlone, Atyrau, Auckland, Aurangabad, Aveiro, Avignon, Avon, Avshalom, Awka, Ayacucho, AyiaNapa, Aywaille, Baabda, Babahoyo, Babakangarut, Bacolod, Bacoor, BadSchwartau, BadVoeslau, BadeDistrict, Badou, Bagarmossen, Bagcilar, Baghdad, Bagsvaerd, BaguimDoMonte, BaieMahault, Baikonur, Baku, Balaclava, Balashikha, Baldone, Ballincollig, Balotesti, Balqash, Balıkesir, Bamako, BanDu, BanKaeng, BanKhoiTai, BanMai, BanThaLuang, BanYanDu, Banaripara, BandaAceh, BandarLampung, BandarSeriBegawan, Bandung, BangBon, BangKruai, BangLamung, Bangkok, BanjaLuka, Banjarnegara, Banov, BanovceNadBebravou, Banovici, BanskáBystrica, Banyuwangi, Baqubah, Barcelona, Barendrecht, Barinas, BarklyWest, Baronissi, Barquisimeto, Barranquilla, Barranquitas, Barrie, BarrigadaVillage, Basel, Baselice, Basiad, Bassens, BatemansBay, Batken, Batman, Batumi, Bauska, Bavikhove, Bayahibe, Bayamón, BayanLepas, Bayanhongor, Bayombong, Bayugan, Beauharnois, BeauneLaRolande, Beawar, Beckenried, Beira, Beirut, Bekasi, Bekkjarvik, Belfast, BelfordRoxo, Belgorod, Belgrade, Bello, Bellville, BeloHorizonte, Beloslav, BelsizePark, Beltinci, Bengaluru, Benghazi, Benguela, BenitoJuarez, Benoni, BentJbail, Berea, Bergamo, Bergen, Berlin, Bern, Bernex, Bestwina, BetShemesh, Beuson, Bexleyheath, Biatorbagy, Bicske, BielskoBiala, BielyKostol, BienHoa, Bilbeis, Billesholm, Biloela, Binan, BingenAmRhein, Birkjeland, Birmingham, Birr, Birsfelden, Bischwiller, Bishkek, BishopSStortford, Bjaeverskov, Bjelovar, Bjorkelangen, Blagoevgrad, Bloemfontein, Boardman, Bobadela, Bodø, Bogor, Bogotá, BohinjskaBistrica, Boise, Bojnice, BoldestiScaeni, Boleraz, Bolivar, Bologna, BonneuilSurMarne, Bool, Borisov, Bornem, Borås, Bosaca, Bostad, Botevgrad, Bouznika, Bozveliysko, Braga, Brampton, Brandon, Brasov, Brasília, Bratislava, BraunauAmInn, Brdo, Bredene, Bredsten, Brescia, Brest, BrezovicaPriLjubljani, Brežice, Bridgetown, Brisbane, Brno, BroadbridgeHeath, Bron, Bronshoj, Broumov, Brovst, BruckAnDerMur, Bruges, Brussels, Bruz, Bryanston, Bryne, Bucaramanga, Bucharest, Buchlovice, Budapest, Budva, Buenaventura, BuenosAires, BukGu, BukitKayuHitam, Bungarribee, BupyeongGu, BuqeiA, Buraidah, Burgas, Burgdorf, Burgos, Bursa, Busan, BusanjinGu, Buscate, Bushey, Busswil, Butuan, Buzau, Bytom, Bytča, Bălţi, CabanatuanCity, Cabimas, Cacem, Cacuaco, Caesarea, CagayanDeOro, Caguas, Caher, Cairo, Cajamarca, Calabar, Calama, Calamba, Calapan, Calgary, Callao, CallosaDeSegura, CaloocanCity, Camaragibe, Cambridge, Cambrils, Camden, Campeche, CampiaTurzii, Campinas, CampoGrande, Camuy, CanaaDosCarajas, Canada, Canals, Canberra, Canovanas, CapeTown, Capellades, CapitanSarmiento, Capurso, Caracas, Caravaca, CardenasSegundaSeccion, Carlisle, CarlosTejedor, Carmen, Carmi, Carmona, Carndonagh, Carrasco, Cartagena, Cartago, Caruaru, Casablanca, CasalnuovoDiNapoli, Cascina, CastelDArio, Castlebar, CastropRauxel, CatalanBay, Catemaco, Catral, CausewayBay, Cavan, Cayenne, Cayey, Cazin, CebuCity, Cejkovice, Celje, CeloricoDeBasto, Central, CerkljeNaGorenjskem, Cerveteri, Chachoengsao, Chaguanas, Chalcis, ChangHua, Changwon, Chania, Chapayevsk, CharcosDeOriente, Charleroi, CharlotteAmalie, CharnecaDeCaparica, Charsadda, ChaumontGistoux, Chaves, Chelsea, Chelyabinsk, Chennai, CheongjuSi, Cheras, Cherepovets, Cherkasy, Chernivtsi, Chesterfield, Chhagalnaiya, ChiangMai, ChiayiCity, ChiayiCounty, Chicago, Chiclayo, Chillan, Chillogallo, Chimbarongo, Chimbote, Chinandega, Chinchvad, Chirpan, Chisinau, Chita, Chittagong, Choconta, Cholargos, CholponAta, Choroszcz, Chorzów, Christchurch, Christiansted, Chyliczki, CiceroDantas, Cienaga, Cisnadioara, Citarum, CityOfMuntinlupa, CiudadBenitoJuarez, CiudadBolívar, CiudadCholuteca, CiudadDelEste, CiudadGuzmán, CiudadJuárez, ClermontFerrand, Clifton, Clitheroe, Clonee, ClujNapoca, Coatepec, Cochabamba, Cofradia, Coimbra, Coka, ColdLake, Colima, ColladoVillalba, Collioure, Collooney, Colombo, Colon, Colón, Comalcalco, Combreux, Comilla, ComodoroRivadavia, Comrat, Conakry, Concepcion, ConcepcionDos, ConcepciónDeLaVega, Concord, ConflansSainteHonorine, Connewarre, Constanța, Copenhagen, Cork, Corlateni, Corozal, Corrientes, Coslada, Coswig, Cotacachi, Cotonou, Cotui, Courcelles, Coventry, Cox, Craiova, Cremona, Crimea, Crodo, Croydon, Cuautlancingo, Cudrefin, Cuenca, Culiacán, Cumpana, Curicó, Curitiba, Curug, Cusco, Cyberjaya, Czerwonak, Częstochowa, CâmaraDeLobos, Córdoba, Căușeni, DaNang, Dadakharka, Daegu, DaiMo, Dalun, Damascus, Damietta, Dammam, Dannike, DarEsSalaam, DavaoCity, David, Dayarampur, Debelets, Debrecen, Dekar, Delft, Delhi, DenBurg, Dendermonde, Depok, DeraGhaziKhan, Derby, Derventa, Destelbergen, Detroit, Dhahran, Dhaka, Dhamar, Dhanbad, Dijon, Dinajpur, DipologCity, Diyarbakır, DlhaNadOravou, Dnipro, Dobele, Doha, DolneSlazany, DolnyOhaj, Dombegyhaz, Domeikava, DonChan, DonTorcuato, Donetsk, DongGu, DongducheonSi, Dorado, Dornach, Dornbirn, Dorsten, DosHermanas, Dourados, DownhamMarket, Dragoman, DrakulicaRijeka, Drochia, Dronten, Druzhino, Dubai, Dublin, DubnicaNadVáhom, Dubno, Dubrovnik, Duhok, Dumalinao, Dunaharaszti, DunajskaLuzna, DunajskáStreda, DundUrt, Dunedin, Dunyapur, Dupnitsa, Durban, Durley, Durrës, Dushanbe, Dzierzoniow, Düsseldorf, Ebaye, Ebeltoft, Ecatepec, EchChettia, Edelira, Edenvale, Edinburgh, Effurun, EgmondBinnen, Eindhoven, Eket, ElGuarenal, ElPinar, ElPratDeLlobregat, ElPueblito, Elbasan, Elche, Encamp, Enebakk, Enkhuizen, Ennis, Enniscorthy, Ennsdorf, EnskedeArstaVantoer, EntreRios, Epping, Erba, Erbil, Ericeira, ErlinsbachAG, Ermelo, Ermesinde, Ermoupoli, Escazu, Escuintla, Eskilstuna, Esmeraldas, Espoo, Esquipulas, Esteli, Eunapolis, Eupen, Eydhafushi, FCT, Fabbrico, Faenza, Faisalabad, Falun, Fangli, Favria, Federacion, Fehervarcsurgo, Fehraltorf, Feira, Felidhoo, Fergana, FernandoDeLaMora, FilipestiiDePadure, Fitjar, Flagstaff, Florence, FlorestaDoAraguaia, Florida, Focşani, Formosa, FortGibson, Fourways, FozDoIguaçu, Framingham, FrankfurtAmMain, Frastanz, FratautiiNoi, FrayLuisBeltran, Fredensborg, Frederiksberg, Freeport, Freetown, Fria, Fukui, Fukuyama, Funchal, Gaborone, Gabrovo, Gabès, Gadoros, Gainesville, Galanta, Galati, GanYavne, GangbukGu, GangdongGu, GangnamGu, Gangtok, Garanhuns, Gardony, Garner, GataDeGorgos, Gaza, Gazipur, Gdansk, Gdynia, Gedera, Geel, Gelse, Gembloux, GeneralLagos, GeneralPico, GeneralRodriguez, GeneralTrias, Geneva, GeojeSi, GeorgeEnescu, GeorgeTown, GerasdorfBeiWien, Getxo, Gevgelija, Ghent, Gibraltar, Gilon, Gisborne, Gistel, GivAtShmuel, Giza, Gjøvik, Glarus, Glattbrugg, Glavinitsa, Gliwice, Glogoczow, Glogovac, GminaOpoleLubelskie, GminaPołaniec, Goalpara, Godstone, Goiânia, GoldCoast, Gomel, GomezPalacio, Gonesse, Goor, Gossau, Gostivar, Gothenburg, GotseDelchev, Gouripur, GoyangSi, Gracanica, Gradacac, Gradignan, Grandola, GravinaInPuglia, Graz, Greenville, Gressvik, Greve, Greystones, Grieskirchen, Grimbergen, Groblersdal, Guadalajara, Guananico, Guane, Guanta, Guarenas, GuatemalaCity, Guatire, Guayama, Guayaquil, Guaynabo, Guelph, Guernsey, Gujrat, Gumi, Gummersbach, Gunpo, Gurlan, GuroGu, GustavoAdolfoMadero, GwacheonSi, GwangjinGu, Gyal, GyeonggiDo, GyeongsanSi, Gyongyos, Gyongyosoroszi, Gyumri, Gävle, HaGosherim, HaLong, Haaksbergen, Haarle, Haarlem, HaciendaIbarra, Hadera, Haderslev, Hafnarfjordur, Hagersten, HaiDuong, Haifa, Haiphong, Hajdusamson, Hajduszoboszlo, Hajnówka, Halden, HallInTirol, Halle, Halstead, Hamamatsu, Hamburg, Hamden, Hamilton, Hammamet, Hamme, Hamoir, Hanakawa, Hangzhou, Hanimaadhoo, Hanoi, Hanover, Harare, Harstad, Haslum, Hasselt, Hastings, Hatne, Hatvan, Hausmening, Havana, Hebron, Hedehusene, Heerbrugg, Heerde, Hejokeresztur, Helmond, Helsingborg, Helsinge, Helsinki, HenndorfAmWallersee, Herat, Heredia, Herfolge, Hernandarias, Herne, HerreraDelDuque, Herve, Herzliya, HighWycombe, Hillerød, Hillingdon, Hillsboro, Hillsdale, Hindisheim, Hinnerup, Hirai, Hirtenberg, HisingsBacka, Hisor, Hjortshoj, Hjørring, Hlinsko, HoChiMinhCity, Hobart, Hochdorf, Hodmezovasarhely, Hohenems, HoiAn, Hokksund, Holbaek, Holenice, Holetown, Holysov, Hommersak, Honefoss, HongKong, HongseongGun, Honiara, Honningsvåg, Horice, Horsens, HradecKrálové, Hrodna, HsinchuCounty, Hualane, Hualqui, Huancayo, Huaquillas, Huaral, Huddinge, Huichapan, Hulhumale, Humacao, Hundven, HungHom, Hunucma, Hvidovre, Hwacheon, HwaseongSi, Hyderabad, Härnösand, Hässleholm, IBillin, Iasi, Ibague, Ibarra, Ibra, Icapui, IcheonSi, Ichibacho, Iguatu, Ikeja, Ilfov, Ilidza, IliganCity, Ilo, Ilulissat, Imatra, Imsida, Inazawa, Indore, Innsbruck, Ioannina, Iquitos, Irkutsk, IsabelSegunda, Isfahan, IslaDeMaipo, Islamabad, IslandBay, Istanbul, Itterbeek, Ituzaingo, Ivancice, IvanoFrankivsk, Iwo, IxellesElsene, IxtlahuacaDeRayon, Izegem, Izmir, Iztacalco, Jabebpur, Jacareí, Jacksonville, Jaco, Jaemjoe, Jakarta, JalalAbad, Janovce, Janze, Jaranwala, Jaszfelsoszentgyorgy, Jati, Jaunmarupe, Jawalakhel, Jeddah, Jelgava, Jember, JemeppeSurSambre, Jerka, Jersey, Jerusalem, JiloveUPrahy, JoaoPinheiro, Johannesburg, JohorBahru, JombangWetan, Jonage, JoseLeonSuarez, JoseMariaMorelos, JuanaDiaz, Juarez, Jubail, Jundiaí, Junglinster, JungnangGu, Juršinci, Jyväskylä, JärfällaMunicipality, Jönköping, Jūrmala, Kabul, Kaduna, KafrManda, Kagoshima, Kajang, Kalamaria, Kalek, Kalemie, Kalibata, Kalihati, Kamenica, KamenskUralsky, Kamiochiai, Kamnik, Kampala, KampungBaharuNilai, Kanazawa, Kangboi, Kanjiza, Kanye, KaohsiungCity, Kapar, Kaprun, Karachi, Karaganda, Karatay, Kardzhali, Karen, Karkazai, Karlstad, Karpacz, Kartal, Kaskhult, Kaski, Kathmandu, Kathwana, Katonah, Kaunas, Kausala, Kavala, Kawasaki, Kayangel, Kayapinar, Kayseri, Kazan, Kazanlak, Keflavik, Kelowna, KemptonPark, Kenitra, KfarSaba, KfarUriyya, KfarYona, Khabarovsk, Kharghar, Kharian, Kharkiv, Khartoum, Khobar, Kiambu, Kidricevo, Kigali, Kilkis, Kimberley, Kingston, Kingstown, Kinsale, Kinsarvik, Kinshasa, Kirchen, Kirkcaldy, KiryatGat, KiryatOno, Kitchener, Klaebu, Klagenfurt, Klaipėda, KlasterecNadOhri, Klaten, Kloten, Knesselare, KnokkeHeist, KoSamui, Kobe, Koblenz, Kobylka, Kochan, Kochi, Koestendorf, Koettmannsdorf, Koishikawa, Kokhma, Kokkedal, Kokshetau, Koksijde, Kolkata, Komen, KomsomolskOnAmur, Komárno, KongensLyngby, Kongsberg, Konya, Koper, Koppigen, Kortrijk, Korydallos, Korçë, Kos, Kostanay, Kostinbrod, KotaBharu, KotaKinabalu, Kotka, Kotli, Kovel, Kowloon, Kozani, Kozhikode, Koziatyn, Košice, Kragujevac, Krakow, KralovskyChlmec, Kramsach, Kranj, Krapina, Krasnogorsk, Kretinga, Kreuzlingen, Kristianstad, Kristinehamn, Krize, Krobia, Kronau, KroscienkoWyzne, Kruševac, Krāslava, Ktis, KualaBelait, KualaLumpur, KualaSelangor, Kuantan, Kufstein, Kulim, Kullavik, Kumba, Kurgan, Kutaisi, Kutina, KutnáHora, KuwaitCity, KwaiChung, Kwidzyn, KwunHang, Kyiv, Kyjov, Kyjovice, Kyrenia, KysuckyLieskovec, KyzylSuu, Kyzylorda, Küssnacht, Kėdainiai, Kırklareli, Kłodzko, LIklin, LaCalera, LaCeiba, LaCruz, LaDorada, LaEntrada, LaFlorida, LaGalera, LaGranja, LaGuaira, LaLibertad, LaLouvière, LaMana, LaPaz, LaPlata, LaQueueEnBrie, LaSaline, LaSerena, LaTroncal, LaXara, Labin, Ladysmith, Lagos, LagunaCarapa, Lahore, Lahug, Lainate, LakeCharles, Lakeland, Laktasi, Lambaré, Lamia, Lampa, Lamphun, Landskron, Langdon, Langenthal, Langhus, Langley, Lanus, Larena, Larnaca, LasChoapas, LasPalmasDeGranCanaria, LasPinas, LasTorresDeCotillas, LatKrabang, Laugarvatn, Laupen, Lausanne, Lauterach, Lauwe, Lazarevac, Lede, Leeds, Leende, LeibnitzStyria, Leicester, Leiden, Leiria, Lekki, Leoben, LesAngles, LesLilas, LesValettes, Lethbridge, Leutenbach, Leuven, Levanger, Levin, León, Liberec, Libertad, LibertadorGeneralSanMartin, Licata, Liepāja, Liezen, Lima, Limanu, Limassol, Limbiate, Limena, Limoeiro, Limón, LinkouDistrict, Linköping, Linz, LiptovskýMikuláš, Lipuvka, Lisbon, Lisburn, Liskova, LittleAttock, Ljubljana, LjubnoObSavinji, Llanquihue, Lliber, Lobao, Lobos, Loddefjord, Lodz, Loehne, Loeningen, LogPriBrezovici, Logatec, Loiza, Loja, Lokeren, Lolodorf, LomasDelMirador, Lomé, London, Longford, LoraDelRio, LosAngeles, LosBanos, LosCardales, LosVilos, Loudon, Loughlinstown, Loule, Loures, Lozen, Luanda, Lublin, Lubochnia, Lubotice, Lucan, Lucens, Lucerne, Luhansk, Luhuan, Lukavac, Lukovica, Lukovit, Luleå, Lumajang, Lumbaqui, Lusaka, Lushnje, Luton, Luxembourg, Lviv, Lyon, LysVa, Lyubertsy, Lyulin, Līsakovsk, MaOnShan, MaYauTong, MaaleIron, Maasbree, Maastricht, Mabalacat, Macao, Maceió, Machala, Machulince, Machupicchu, Mackovci, Macouria, Macul, Made, Madinabad, MadinatAnNasr, MadinatHamad, MadinatIsa, Madrid, Mafra, Magalang, Magdacesti, MagnesiaAdSipylum, MahaSarakham, Maia, Maidenhead, Mailberg, Maipu, Mairinque, Majuro, Makarska, MakatiCity, Makhachkala, Makkah, Makuharihongo, MalaTrna, Malabo, Malang, Maldegem, Malden, Maldonado, Male, Malinovo, Malmo, MalvinNorte, Malé, Mamoudzou, ManKok, Manacor, Managua, Manama, Manati, Manaus, Manchester, Mandal, Manila, Manizales, Manta, MapoGu, Maputo, MarDelPlata, Marabu, Maracaibo, Maracay, Maracineni, Marang, Marcinelle, Maribor, Mariehamn, Marijampolis, Marijampolė, Marilao, Marituba, MariánskéLázně, Marrakesh, Marsabit, Marseille, Martin, Masala, Masein, Masionys, Matay, Mateare, Matera, Matola, MatosinhosMunicipality, Matoury, Matsudo, Maule, MayPen, Mayagüez, Mazyr, Mažeikiai, Mbabane, Medellín, Medina, MedjezElBab, Meieki, Mejicanos, Melbourne, Melipilla, Mendoza, Merano, Merate, MerthyrTydfil, Messancy, Metamorfosi, MetzTessy, Metzervisse, Mexicali, MexicoCity, Mezzovico, Miami, Miaoli, Michalovce, MidLevels, Middelburg, Mielec, MiercureaCiuc, Mikageishimachi, Mikulov, Milagro, Milan, Milwaukee, Minatomirai, MineralDeLaReforma, Minglanilla, Minneapolis, Minsk, Miranda, Miriniskiai, Mirpur, Misratah, Mississauga, Mito, Mixco, Miyamachi, Mlini, MoIRana, Moca, Mocoa, ModiInMakkabbimReUt, Moerkapelle, Mogadishu, Mogilev, MoglianoVeneto, Mogyorod, Mollendo, Mollis, Mombasa, Monaco, Mons, MonsEnBaroeul, MontBuxton, Montalenghe, MonteMaiz, MontegoBay, Montero, Monterrey, Montevideo, Montijo, Montirone, Montmorency, Montreal, Moordrecht, Mor, Morschwil, Moscow, Mostar, Mosul, Mozirje, Mragowo, Mthatha, Mugla, Muhlau, Muhos, Mulhouse, Multan, Mumbai, Muna, Munich, Munoz, Murcia, Murmansk, Muscat, Myslenice, Mérida, Mérignac, Mönchengladbach, Mörön, Münster, Naaldwijk, Nablus, Nafplion, Nagahama, Naguabo, Nagybajcs, Nagykoroes, Naha, Nahariya, Nairobi, Naivasha, Nakhodka, NakhonPathom, NakhonRatchasima, NakhonSawan, Naklo, Nakuru, NamGu, Namsos, Namyangju, NamĐịnh, Nantes, NapierCity, Naples, Narangba, Naranjito, Narva, NaselbaCaska, Nassau, Nauen, Navoiy, Navotas, Naxxar, Nazareth, NeaLiosia, NeaPeramos, Neiva, Nemby, Nemenčinė, Nenagh, Nes, Nesoddtangen, Nesttun, Netanya, NewDelhi, NewPlymouth, NewTaipei, NewcastleUponTyne, NewportCoast, Nezvestice, Ngawi, Ngetkib, Nicosia, Niedergosgen, Niederuzwil, Niel, Niepolomice, Nierada, Nieuwpoort, Nijmegen, Nimtofte, Nindiri, NinhBinh, Ninove, Nishihokima, Nishikicho, Nishioizumi, Nisporeni, Nisshincho, Nitra, Nivnice, NizzaneOz, Niš, Nogales, Noida, Nokata, Nokia, Nonthaburi, Norager, Norresundby, Norrköping, Norsborg, NorthVancouver, Northampton, NorwayHouse, Noshiro, Nouakchott, Noumea, NovaFriburgo, NovaGorica, NovaGradiska, NovaVasNadDragonjo, NovaZagora, Noves, NoviDiModena, NoviLigure, NoviSad, NoviTravnik, NovoMesto, NovéZámky, NowySącz, NuevoLaredo, NurSultan, Nuremberg, Nussbaumen, Nusshof, Nyergesujfalu, Nyköping, Námestovo, Nîmes, OaxacaCity, Oberentfelden, Oberrohrdorf, Obervellach, Obosi, Odder, Odense, Odivelas, Oeiras, Ogre, Ohrid, Oiba, Okara, Okayama, Oldenzaal, Olivos, Ollon, Olomouc, Omorinishi, Omsk, Onex, Oostduinkerke, Oosterhout, Opava, Oplotnica, Opole, OpstinaArandelovac, Oradea, Oral, Oranjestad, Ordacsehi, OrihuelaCosta, OrlandPark, Orléans, Ormoz, OrpJauche, Orsk, Osaka, Osan, Oslo, Osogbo, Osorno, Ostermundigen, Ostrava, OstrówWielkopolski, Otemae, Oto, Ouagadougou, Oulu, Outes, Ovalle, Oxentea, Oxford, Ozamiz, OzarowMazowiecki, Ozolnieki, Paarl, Pabaži, Pabianice, Pacov, PadreCarvalho, Paea, Paget, Paita, Paju, Pakruojis, Palanga, Palangkaraya, Palash, Palma, Palmas, PalmersGreen, PalmerstonNorth, PaloNegro, Pamukkale, PanamaCity, Panchdona, Pandrup, Panevezys, Panjakent, Panjim, Panti, Papakura, Papeete, Paphos, Paralimni, ParanaqueCity, Paraná, Pardubice, Parecis, Paris, ParmaHeights, Partizánske, Parvomay, Parys, Pasaje, Pasig, Paskov, Pasto, Pastrana, Pasuruan, PathumThani, Patna, Pattani, Paulista, Pavas, Pavlodar, Pazmandfalu, PaçosDeFerreira, Pedernales, Pelhrimov, Pembroke, Penaflor, Peniche, Pepowo, Pereira, PerezZeledon, Pergamino, Perico, Perth, Peshawar, Pesqueria, PetahTikva, PetalingJaya, Peterborough, Petershausen, PetitBourg, Petrila, Petrolina, Petropavl, Pezinok, Pfaffendorf, Philadelphia, Phitsanulok, PhnomPenh, Phoenix, Phuket, PianoDelVoglio, Pias, PichlBeiWels, Piedecuesta, PiedrasBlancas, Pierrefonds, PiggsPeak, Pilar, Pilsen, Pinagbuhatan, Pinamalayan, PingtungCity, PingzhenDistrict, Pinofranqueado, Pinzolo, PiotrkowKujawski, PipeCreek, Piracicaba, Piraeus, Pissouri, Pleven, Plogonnec, Ploieşti, Plovdiv, PocheonSi, Pocitos, Podgorica, Pogradec, Pohang, PointeÀPitre, Poltava, Polzela, Ponce, PontSaintMartin, PonteDaBarca, Popovo, Poprad, Porlamar, PortElizabeth, PortHarcourt, PortMoresby, PortaWestfalica, Portlaoise, Portmore, Porto, PortoAlegre, PortoSeguro, Portorož, Portoviejo, Porvoo, Porzuna, Postira, Potosí, PovažskáBystrica, PovoaDeSantoAdriao, PozaRicaDeHidalgo, Poznan, Prague, Praha11, Praia, PratolaPeligna, Pravets, Preles, Prelouc, PresidenciaDeLaPlaza, Pretoria, Preveza, Prešov, Pribeta, Prienai, Prilep, Pristina, Prosperidad, ProvinceOfRizal, ProvinciaDeElOro, Provodin, Pskov, PuchongBatuDuaBelas, Pucon, Pudasjärvi, PueblaCity, Puebloviejo, PuenteAlto, PuertoBaquerizoMoreno, PuertoCortez, PuertoEldorado, PuertoFranciscoDeOrellana, PuertoLumbreras, PuertoPlata, PuertoRico, Pula, Pune, PuntaDelEste, Puntarenas, Purkersdorf, Puspokhatvan, Pusztazamor, Putaendo, Putignano, Puurs, Pyla, Pátrai, Písek, Quarteira, QuatreBornes, Quba, Queenstown, QuerétaroCity, Quesada, Quetzaltenango, Quevedo, QuezonCity, QuiNhon, QuintaNormal, Quito, Québec, QuảngNgãi, Raanana, Rabat, Racovita, Radal, Radauti, Radom, Radomlje, Radviliškis, Radzionkow, Rafaela, RahimYarKhan, Rajshahi, Rakovski, Ramallah, RamatGan, Rambouillet, Ramla, Rancagua, Randers, Ransdaal, RasAlKhaimah, RasTanura, Ratoath, Ratomka, Raub, Rauna, Rawalpindi, Rawang, Rayleigh, Recife, RedDeer, Reda, Redditch, Redencao, Redkino, Regau, Regavim, Regina, Reims, Relov, RemireMontjoly, Rence, Repin, Requinoa, Resistencia, Rethymno, Reutlingen, Revivim, Revúca, Reyhanli, Reykjanesbaer, Reykjavik, Rho, RichmondHill, Riehen, Riemst, Riga, Rijeka, RillieuxLaPape, RioDeJaneiro, RioDeMouro, RioGrande, RioMaior, RioSegundo, Riobamba, Rioja, Rioverde, RishonLeTsiyyon, Risskov, Ritthem, Riverhead, RiviereSalee, Riyadh, Roatan, Rochester, Rocinj, Rodgau, RohrbachInOberoesterreich, Rome, Ronneburg, Ronse, RoquePerez, Rosario, Roseau, RoshHaAyin, Roslev, RostovOnDon, Rottenegg, Rovaniemi, Royken, RtyneVPodkrkonosi, Rudnyy, RumillyEnCambresis, Rupperswil, Ruše, Ružomberok, Rybnik, Ryugasaki, Rzeszów, RâmnicuVâlcea, RíoCuarto, Rîbniţa, Sabac, Sabadell, SabakBernam, Sabbioneta, Sacalaz, Saevsjoe, Safi, SahaGu, SaintAndrew, SaintAthanasios, SaintDenis, SaintHelier, SaintJosseTenNoode, SaintLaurentNouan, SaintPriestEnJarez, SaintPriestLaVetre, SainteMarie, Sakaecho, Sakaemachi, Salaspils, Salavaux, Saldungaray, Salgotarjan, Sallent, Salou, SalsomaggioreTerme, Salta, Saltillo, Salto, Saltykovka, Salvador, SalvaterraDeMagos, Salwa, Salzburg, Salé, SamPhran, SamoraCorreia, Samorin, Samsun, SamutPrakan, SanAntonio, SanAntonioDeLosAltos, SanFelipe, SanFelipeDelProgreso, SanFernando, SanFrancisco, SanFranciscoTelixtlahuaca, SanGwann, SanIsidro, SanJoseDeFeliciano, SanJoseDelMonte, SanJosé, SanJuan, SanJuanBautistaTuxtla, SanJuanDeAbajo, SanJuanDeLurigancho, SanLorenzo, SanLorenzoDeEsmeraldas, SanLuisPotosíCity, SanMarcos, SanMateoDeGallego, SanMiguel, SanMiguelDeTucumán, SanPedro, SanPedroDeMacorís, SanPedroSula, SanSalvador, SanSalvatoreMonferrato, SanVicenteDeAlcantara, SanVicenteDeTaguaTagua, SanVicenteDelCaguan, Sanaa, Sandefjord, Sandomierz, Sandton, SanktAndrae, SanktLeonhardAmForst, Sanom, SantAndreuDeLaBarca, SantFruitosDeBages, SantaClara, SantaColoma, SantaCruz, SantaCruzDaTrapa, SantaCruzDeBarahona, SantaCruzDoSul, SantaCruzTlaxcala, SantaFe, SantaLuciaDiSerino, SantaMaria, SantaMarta, SantaRita, SantaRosa, SantaRosaDeCopán, SantaTeresita, Santiago, SantiagoDeCali, SantiagoDeCompostela, SantiagoDeLosCaballeros, SantoAntonioDePadua, SantoDomingo, SantoDomingoDeLosColorados, SantoDomingoEste, SantoDomingoOeste, SantoEstevao, SaoBartolomeuDeMessines, SaoLourencoDaMata, SaoPedroDoSuacui, SaoTeotonio, Sapele, Sapporo, Sarajevo, Sathon, Sattahip, SatuMare, Savalou, SavarUpazila, Schaan, Schilde, Schoelcher, Scottsdale, Seeb, SeekirchenAmWallersee, Seixal, Sejong, Sellebakk, Semarang, Senec, Seneffe, Senges, SenhorDoBonfim, SeoGu, SeochoGu, SeodaemunGu, SeongbukGu, SeongdongGu, SeongnamSi, Seoul, Serang, Serock, Serracapriola, Serres, SestoSanGiovanni, Sesvete, Sevastopol, Seveso, Seville, Sevlievo, Sevran, Sfax, ShaTinWai, ShahAlam, Shankill, Sharjah, Shatin, Shepetivka, Shinchiba, Shinkocho, Shiraitodai, Shizuoka, Shkoder, Shoham, Shtip, Shymkent, SiRacha, Sialkot, Sidon, Siebnen, Siegen, Sierpc, Sierre, Siguatepeque, Sigulda, Silbertal, Silistra, Silkeborg, Simferopol, Sincelejo, Singera, SintMartensLatem, SintNiklaas, SintOdilienberg, Sintra, Sion, Sipalay, Sirmione, SirokiBrijeg, Sixmilebridge, Sjoebo, Skaerholmen, Skanderborg, Skellefteå, Ski, Skiptvet, Skive, Skjaerhalden, Skofljica, Skogas, Skopje, Skouriotissa, Skövde, Slatina, SlavonskiBrod, Sliema, Sligo, Slough, SlovenskaBistrica, Smarje, SmarjePriJelsah, Smederevo, Smiltene, Smolensk, Sniatyn, SoedraSunderbyn, Sofia, Sohar, Sokcho, SokoBanja, Sollentuna, Sombor, Son, SonServera, SongpaGu, Sonson, SonsorolVillage, Soreide, Sorriso, SouthNutfield, SouthTangerang, SouthendOnSea, Soyapango, Spencerville, SpišskáNováVes, Split, Spomysl, Sprundel, StAlbans, StCroix, StGallen, StJohnS, StJulianS, StPetersburg, Stallikon, Stamboliyski, Stans, StaraCerkev, StaraZagora, Stargard, Starmen, Stavanger, Steinkjer, Steszew, StitnaNadVlari, Stockholm, Storebo, Strakonice, Stramberk, Stranice, Stranraer, Strasbourg, Strmec, Strovolos, StruerMunicipality, Struga, Strumica, Strusshamn, Studley, Sturkoe, Subotica, SukabumiUtara, Sulaymaniyah, Suleja, Sumperk, Sumy, Sunbury, SunshineCoast, Surabaya, Surahammar, Surakarta, Surat, Surgut, Surquillo, SuseongGu, Sutton, Suwon, Svendborg, Sveshtari, SvetiNikole, Swabi, Swieqi, Swords, Sydney, Sykkylven, Sylhet, Szczecin, Szeged, Szentgotthard, Szigetszentmiklos, SãoJoséDosCampos, SãoPaulo, Sønderborg, Taastrup, Tachilek, TaclobanCity, Tacoma, Taichung, TaichungCity, TainanCity, Taipei, TaipeiCity, Taiping, Takamatsu, Talagante, Talarrubias, Talas, Talca, Talcahuano, Taldykorgan, TalisayCity, Tallinn, Talsi, Tampere, Tampico, Tamuning, TanAn, Tandil, Tanga, Tangerang, Tangier, Tangjin, TaoyuanDistrict, Tapachula, Taraclia, Tarancon, Taraz, Tarija, Tarm, Tarnobrzeg, TarnowskieGory, TashKumyr, Tashir, Tashkent, Tasman, Tatebayashi, Tau, Taulihawa, Taunsa, Tauragė, TayNinh, Tbilisi, TeAwamutu, Teckomatorp, Tegalsari, Tegucigalpa, Tehran, TeixeiraDeFreitas, Tejgaon, TelAviv, Telki, Temanggung, Temara, Templepatrick, Tena, Tepelenë, Teresina, Ternopil, Tetange, Texcoco, Thalgau, Thamaga, Thane, TheBronx, Thermi, Thessaloniki, Thika, Thimphu, Thiruvananthapuram, ThuDauMot, ThuanAn, Thun, Thurn, Tibas, Tielt, Tighina, Tihuatlan, Tijuana, Tilburg, Timișoara, TinhBinhDuong, Tipitapa, Tipperary, Tirana, Tisnov, Tiszakecske, Titel, TlajomulcoDeZuniga, Tlalnepantla, ToaAlta, Tobecho, Tofte, Togo, Tokyo, Toliara, Tolmin, Toluca, Tombolo, Tome, Tonala, Topolovets, Topoľčany, Toretsk, Toronto, Torrellano, Torremolinos, Torup, Touguinha, Toulon, Tours, TraVinh, Tralee, Trang, Tregnago, Trento, Trenčín, Treviolo, Trindade, Trinec, Tripoli, Trnava, Trnov, Tromsdalen, Trondheim, Trujillo, TrujilloAlto, Trullikon, Trzcianka, Trzebinia, Trzebnica, Tsarevo, Tsimasham, Tsu, TuenMun, Tukums, Tulkarm, TultitlanDeMarianoEscobedo, Tunasan, Tunis, Tunja, Turin, Turjak, Turku, Turnisce, Turrialba, TuxtlaGutiérrez, Tver, Tyachiv, Tyumen, Tábor, TârguJiu, TârguMureş, Ube, Uddevalla, Uetersen, UijeongbuSi, Ukmerge, UlanBator, Ulldecona, Ulm, Umeå, Unterterzen, UpplandsVasby, Uppsala, Ussuriysk, UstKamenogorsk, Utena, Utrecht, Utuado, Uzhhorod, Vaasa, Vacszentlaszlo, Vakarel, ValasskeMezirici, Valby, ValeaLupului, ValeaRamnicului, Valencia, Valenzano, Valenzuela, Valladolid, Vallenar, Valmiera, Van, Vanadzor, Vancouver, Vanderbijlpark, Vantaa, Varazze, Varna, Varsta, VauxSousChevremont, Vaxjo, Vecs, Vecses, Veghel, Vejle, Velence, VelikaJamnicka, Velikovtsi, VelkePavlovice, Vellinge, VenadoTuerto, Vence, VendasNovas, Venice, Venlo, Ventspils, VeseliNadLuznici, Vetlanda, VianaDoCastelo, Vidin, Vidovec, Viedma, Vienna, Vientiane, VieuxGenappe, Viganello, Vigo, VilaNovaDeGaia, VilaRica, VilaVerde, VillaConstitucion, VillaDelTotoral, VillaHidalgo, VillagarciaDeLaTorre, Villahermosa, Villamontes, Villarrica, Villavicencio, VilleneuveLaGarenne, Villiersdorp, Vilnius, Vinces, Vinica, Vinnytsia, Virginia, Viskovo, Viterbo, VitóriaDaConquista, Vladesti, Vladivostok, Vladni, Vlamertinge, Vodice, Volendam, VoltaRedonda, Voluntari, Voorhout, Voronezh, Votuporanga, Vrable, Vranje, Vratnica, Vratsa, Vriezenveen, Vsetin, Vukovar, Vuzenica, VysneRaslavice, VysokeMyto, Västerås, VũngTàu, Waarde, Waddinxveen, Waikato, WainsanDaThatta, Wakefield, Walthamstow, Warsaw, Waterloo, Wattrelos, Wellington, Wendeburg, Wenzendorf, WestBayRoad, Westzaan, Wettingen, Wetzikon, Whangarei, WiangSa, Wielsbeke, WienerNeudorf, WienerNeustadt, Wil, Windhoek, Winnsboro, Wintelre, Winterthur, WitkowSlaski, Wlodawa, Woburn, Wolbrom, Wollongong, WoluweSaintLambert, Wroclaw, Włocławek, Xanthi, XinyingDistrict, XinzhuangDistrict, Yabucoa, Yakutsk, Yalova, Yalta, Yambol, Yangju, YangmeiDistrict, Yangon, YangpYong, Yanuh, Yaoundé, Yatova, YauTsimMong, Yekaterinburg, Yeoju, Yeongju, YeonjeGu, Yerevan, YigoVillage, Yogyakarta, Yokohama, Yonezawa, YonginSi, YongsanGu, Yungay, Yunlin, YuseongGu, Yusufeli, Yuto, YverdonLesBains, Zaandam, ZacatecasCity, Zagreb, Zalaszentgrot, ZamboangaCity, Zambrów, Zapopan, Zapotiltic, Zaria, Zarqa, Zatory, Zavidovici, Zavrc, Zeist, ZellAmSee, Zelzate, Zemen, Zenica, Zetaquira, Zgierz, ZgornjeGorje, ZhongliDistrict, Zhubei, Zhytomyr, Zivinice, Zlatitsa, Zlín, Znojmo, Zonguldak, Zorak, Zrece, Zulia, Zuoying, Zurich, Zuwarah, Zvolen, Ávila, Ängelholm, Ålesund, Épendes, Érd, Óbidos, Örebro, Östersund, Čakovec, ČeskéBudějovice, ČeskýTěšín, Šahy, Šalčininkai, Šentjernej, Žalec, Žilina

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxParallelism
Maximum concurrent health checks within a single domain run.

```yaml
Type: Int32
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxResultsToKeep
Maximum number of resolver results retained in the view (default: 500).

```yaml
Type: Int32
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverMaxParallelism
Maximum number of resolvers to query in parallel (null = all).

```yaml
Type: Int32
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverStrategy
Strategy used when multiple DNS endpoints are provided.

```yaml
Type: MultiResolverStrategy
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values: FirstSuccess, FastestWins, SequentialFallback, RoundRobin, Random

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OpenInBrowser
Open export in browser when applicable.

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: OpenReport
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RecordType
DNS record type to test.

```yaml
Type: DnsRecordType
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values: Reserved, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, PX, AAAA, LOC, NXT, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT, APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA, SMIMEA, HIP, NINFO, RKEY, TALINK, CDS, CDNSKEY, OPENPGPKEY, CSYNC, ZONEMD, SVCB, HTTPS, SPF, LP, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY, URI, CAA, AVC, DOA, AMTRELAY, RESINFO, TA, DLV

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServersFile
Path to JSON file with DNS servers.

```yaml
Type: String
Parameter Sets: ServersFile
Aliases: None
Possible values:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SnapshotPath
Directory used to store DNS snapshots.

```yaml
Type: String
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Take
Limit the number of servers queried.

```yaml
Type: Int32
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ThrottleLimit
Maximum number of concurrent items for cmdlet-level parallel work.

```yaml
Type: Int32
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `None`

## RELATED LINKS

- None
