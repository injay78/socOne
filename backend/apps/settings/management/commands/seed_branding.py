import json
from pathlib import Path

from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand

from apps.settings.models import BrandingConfig
from apps.settings.runtime_config import invalidate

TEXT_FIELDS = ("product_name", "product_short_name", "primary_color", "accent_color")
IMAGE_FIELDS = ("logo_full", "logo_compact", "logo_mark", "logo_dark", "favicon", "login_background")


class Command(BaseCommand):
    help = "Load branding identity from a fixture directory into BrandingConfig."

    def add_arguments(self, parser):
        parser.add_argument(
            "--fixture-dir",
            default="deploy/fixtures/shb-branding",
            help="Directory containing branding.json and image files.",
        )

    def handle(self, *args, **options):
        fixture_dir = Path(options["fixture_dir"])
        manifest_path = fixture_dir / "branding.json"
        if not manifest_path.exists():
            self.stderr.write(self.style.ERROR(f"Not found: {manifest_path}"))
            return

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        config = BrandingConfig.get_current()

        for field in TEXT_FIELDS:
            if field in manifest and manifest[field]:
                setattr(config, field, manifest[field])

        config.save()

        for field in IMAGE_FIELDS:
            filename = manifest.get(field, "")
            if not filename:
                continue
            file_path = fixture_dir / filename
            if not file_path.exists():
                self.stderr.write(self.style.WARNING(f"Skipped {field}: {file_path} not found"))
                continue
            getattr(config, field).save(filename, ContentFile(file_path.read_bytes()), save=True)

        invalidate("branding")

        self.stdout.write(self.style.SUCCESS(f"Branding loaded from {fixture_dir}"))
        self.stdout.write(f"  product_name:       {config.product_name}")
        self.stdout.write(f"  product_short_name: {config.product_short_name}")
        self.stdout.write(f"  primary_color:      {config.primary_color}")
        self.stdout.write(f"  accent_color:       {config.accent_color}")
        for field in IMAGE_FIELDS:
            value = getattr(config, field)
            self.stdout.write(f"  {field:20s} {value.name if value else '(empty)'}")
