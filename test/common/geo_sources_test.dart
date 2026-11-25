import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yaml/yaml.dart';

void main() {
  const profile = {GeoResource.GEOSITE: 'https://profile.test/geosite.dat'};
  const settings = PatchClashConfig(
    geoXUrl: {GeoResource.GEOIP: 'https://app.test/geoip.dat'},
  );

  test('a new or restored old settings file prefers the profile', () {
    expect(const PatchClashConfig().preferProfileGeoSources, isTrue);
    expect(PatchClashConfig.fromJson({}).preferProfileGeoSources, isTrue);
    final restored = PatchClashConfig.fromJson(
      jsonDecode(jsonEncode(settings.copyWith(preferProfileGeoSources: false)))
          as Map<String, Object?>,
    );
    expect(restored.preferProfileGeoSources, isFalse);
  });

  test('each missing profile URL falls back independently', () {
    final urls = effectiveGeoSources(profile, settings);
    expect(urls[GeoResource.GEOSITE], profile[GeoResource.GEOSITE]);
    expect(urls[GeoResource.GEOIP], settings.geoXUrl[GeoResource.GEOIP]);
    expect(urls[GeoResource.MMDB], defaultGeoXUrl[GeoResource.MMDB]);
    expect(urls[GeoResource.ASN], defaultGeoXUrl[GeoResource.ASN]);
  });

  test('app preference ignores all profile URLs', () {
    final urls = effectiveGeoSources(
      profile,
      settings.copyWith(preferProfileGeoSources: false),
    );
    expect(urls[GeoResource.GEOSITE], defaultGeoXUrl[GeoResource.GEOSITE]);
  });

  test('malformed resource entries cannot discard the valid sources', () {
    expect(
      profileGeoSources({'geosite': ' ', 'geoip': 42, 'unknown': 'x'}),
      isEmpty,
    );
    expect(profileGeoSources('not a mapping'), isEmpty);
  });

  test('the effective URLs reach the generated profile', () async {
    final result = await makeRealProfileTask(
      MakeRealProfileState(
        profilesPath: '/profiles',
        profileId: 1,
        rawConfig: {
          'geox-url': {'geosite': profile[GeoResource.GEOSITE]},
          'rules': ['GEOSITE,apple-music,DIRECT'],
        },
        realPatchConfig: settings,
        overrides: const ProfileOverrides(),
        appendSystemDns: false,
        proxyGroups: const [],
        rules: const [],
        addedRules: const [],
        defaultUA: 'FlClash-Test',
      ),
    );
    final config = loadYaml(result.yaml) as YamlMap;
    expect(config['geox-url']['geosite'], profile[GeoResource.GEOSITE]);
    expect(config['geox-url']['geoip'], settings.geoXUrl[GeoResource.GEOIP]);
    expect(config['rules'], contains('GEOSITE,apple-music,DIRECT'));
  });
}
