import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';

Map<GeoResource, String> profileGeoSources(Object? value) {
  if (value is! Map) return const {};
  return {
    for (final type in GeoResource.values)
      if (value[type.configKey] case final String url
          when url.trim().isNotEmpty)
        type: url.trim(),
  };
}

Map<GeoResource, String> effectiveGeoSources(
  Map<GeoResource, String> profile,
  PatchClashConfig settings,
) => {
  ...defaultGeoXUrl,
  ...settings.geoXUrl,
  if (settings.preferProfileGeoSources) ...profile,
};
