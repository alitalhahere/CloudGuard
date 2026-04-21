#!/usr/bin/env python3
"""
CLI entry point for CloudGuard.
"""

import click
from .scanner import AWSMisconfigScanner

@click.command()
@click.option('--profile', '-p', default=None, help='AWS profile name (from ~/.aws/credentials)')
@click.option('--output', '-o', type=click.Choice(['table', 'json']), default='table', help='Output format')
def main(profile, output):
    """CloudGuard – AWS misconfiguration scanner."""
    click.echo("🔒 CloudGuard – AWS Security Scanner\n")
    scanner = AWSMisconfigScanner(profile_name=profile)
    scanner.run_all_scans()
    report = scanner.generate_report(output_format=output)
    click.echo(report)

if __name__ == '__main__':
    main()
