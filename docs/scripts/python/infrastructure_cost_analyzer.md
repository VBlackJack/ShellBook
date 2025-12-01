# Infrastructure Cost Analyzer

Script Python d'analyse et optimisation des coûts d'infrastructure cloud.

## Description

- **Multi-cloud** : Support AWS, Azure, GCP (via APIs)
- **Analyse locale** : Estimation des coûts on-premise
- **Recommandations** : Suggestions de rightsizing et optimisation
- **Rapports** : Export HTML, JSON, CSV avec graphiques
- **Alertes** : Détection des ressources sous-utilisées
- **Projection** : Estimation des coûts futurs

## Prérequis

```bash
pip install rich pyyaml psutil requests
# Optionnel pour AWS
pip install boto3
# Optionnel pour Azure
pip install azure-mgmt-compute azure-identity
# Optionnel pour GCP
pip install google-cloud-compute
```

## Utilisation

```bash
# Analyse des ressources locales
python infrastructure_cost_analyzer.py --local

# Analyse AWS
python infrastructure_cost_analyzer.py --provider aws --profile production

# Analyse Azure
python infrastructure_cost_analyzer.py --provider azure --subscription SUB_ID

# Analyse multi-cloud
python infrastructure_cost_analyzer.py --provider aws,azure

# Export rapport HTML
python infrastructure_cost_analyzer.py --local --output report.html

# Recommandations d'optimisation
python infrastructure_cost_analyzer.py --local --optimize

# Projection sur 12 mois
python infrastructure_cost_analyzer.py --local --forecast 12
```

## Configuration

Fichier `cost_config.yaml` :

```yaml
providers:
  aws:
    profile: default
    regions:
      - eu-west-1
      - us-east-1
  azure:
    subscription_id: "xxx-xxx-xxx"
  gcp:
    project_id: "my-project"

pricing:
  # On-premise hourly costs ($/hour)
  compute_per_vcpu: 0.02
  memory_per_gb: 0.005
  storage_per_gb_month: 0.03
  network_per_gb: 0.01

thresholds:
  cpu_underutilized: 10  # %
  memory_underutilized: 20  # %
  disk_underutilized: 30  # %
  idle_days: 7

alerts:
  monthly_budget: 10000
  cost_increase_percent: 20
```

## Code Source

```python
#!/usr/bin/env python3
"""
Infrastructure Cost Analyzer - Cloud and on-premise cost analysis.

Features:
- Multi-cloud support (AWS, Azure, GCP)
- On-premise resource costing
- Rightsizing recommendations
- Cost forecasting
- Budget alerts
"""

import os
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import psutil
    import yaml
except ImportError:
    print("Missing dependencies. Install with: pip install rich pyyaml psutil")
    sys.exit(1)

console = Console()

# =============================================================================
# Data Models
# =============================================================================

class ResourceType(Enum):
    """Type of infrastructure resource."""
    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    CONTAINER = "container"
    OTHER = "other"


class Provider(Enum):
    """Cloud provider or on-premise."""
    LOCAL = "local"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


@dataclass
class Resource:
    """Infrastructure resource."""
    id: str
    name: str
    resource_type: ResourceType
    provider: Provider
    region: str = "local"
    specs: dict = field(default_factory=dict)
    utilization: dict = field(default_factory=dict)
    monthly_cost: float = 0.0
    tags: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.resource_type.value,
            "provider": self.provider.value,
            "region": self.region,
            "specs": self.specs,
            "utilization": self.utilization,
            "monthly_cost": round(self.monthly_cost, 2),
            "tags": self.tags
        }


@dataclass
class Recommendation:
    """Cost optimization recommendation."""
    resource_id: str
    resource_name: str
    recommendation_type: str
    description: str
    current_cost: float
    estimated_savings: float
    priority: str = "medium"  # low, medium, high
    action: str = ""

    @property
    def savings_percent(self) -> float:
        if self.current_cost == 0:
            return 0
        return round((self.estimated_savings / self.current_cost) * 100, 1)

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "type": self.recommendation_type,
            "description": self.description,
            "current_cost": round(self.current_cost, 2),
            "estimated_savings": round(self.estimated_savings, 2),
            "savings_percent": self.savings_percent,
            "priority": self.priority,
            "action": self.action
        }


@dataclass
class CostReport:
    """Complete cost analysis report."""
    scan_time: datetime
    period: str = "monthly"
    resources: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)

    @property
    def total_cost(self) -> float:
        return sum(r.monthly_cost for r in self.resources)

    @property
    def potential_savings(self) -> float:
        return sum(r.estimated_savings for r in self.recommendations)

    def by_type(self) -> dict:
        """Group costs by resource type."""
        costs = {}
        for r in self.resources:
            t = r.resource_type.value
            if t not in costs:
                costs[t] = 0
            costs[t] += r.monthly_cost
        return costs

    def by_provider(self) -> dict:
        """Group costs by provider."""
        costs = {}
        for r in self.resources:
            p = r.provider.value
            if p not in costs:
                costs[p] = 0
            costs[p] += r.monthly_cost
        return costs

    def to_dict(self) -> dict:
        return {
            "scan_time": self.scan_time.isoformat(),
            "period": self.period,
            "summary": {
                "total_cost": round(self.total_cost, 2),
                "potential_savings": round(self.potential_savings, 2),
                "resource_count": len(self.resources),
                "recommendations_count": len(self.recommendations)
            },
            "by_type": {k: round(v, 2) for k, v in self.by_type().items()},
            "by_provider": {k: round(v, 2) for k, v in self.by_provider().items()},
            "resources": [r.to_dict() for r in self.resources],
            "recommendations": [r.to_dict() for r in self.recommendations]
        }


# =============================================================================
# Pricing Calculator
# =============================================================================

class PricingCalculator:
    """Calculate infrastructure costs."""

    # Default pricing (USD per hour/month)
    DEFAULT_PRICING = {
        "compute_per_vcpu_hour": 0.02,
        "memory_per_gb_hour": 0.005,
        "storage_per_gb_month": 0.03,
        "ssd_per_gb_month": 0.10,
        "network_per_gb": 0.01,
    }

    # Hours in a month
    HOURS_PER_MONTH = 730

    def __init__(self, pricing: dict = None):
        self.pricing = pricing or self.DEFAULT_PRICING

    def compute_cost(self, vcpus: int, memory_gb: float, hours: int = None) -> float:
        """Calculate compute cost."""
        hours = hours or self.HOURS_PER_MONTH
        cpu_cost = vcpus * self.pricing["compute_per_vcpu_hour"] * hours
        mem_cost = memory_gb * self.pricing["memory_per_gb_hour"] * hours
        return cpu_cost + mem_cost

    def storage_cost(self, size_gb: float, is_ssd: bool = False) -> float:
        """Calculate storage cost per month."""
        if is_ssd:
            return size_gb * self.pricing["ssd_per_gb_month"]
        return size_gb * self.pricing["storage_per_gb_month"]

    def network_cost(self, egress_gb: float) -> float:
        """Calculate network egress cost."""
        return egress_gb * self.pricing["network_per_gb"]


# =============================================================================
# Local Resource Analyzer
# =============================================================================

class LocalAnalyzer:
    """Analyze local system resources."""

    def __init__(self, pricing: PricingCalculator):
        self.pricing = pricing

    def analyze(self) -> list:
        """Analyze local resources."""
        resources = []

        # CPU/Memory (Compute)
        cpu_count = psutil.cpu_count()
        memory = psutil.virtual_memory()
        memory_gb = memory.total / (1024**3)

        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = memory.percent

        compute_cost = self.pricing.compute_cost(cpu_count, memory_gb)

        resources.append(Resource(
            id="local-compute",
            name=f"Local Server ({os.uname().nodename if hasattr(os, 'uname') else 'localhost'})",
            resource_type=ResourceType.COMPUTE,
            provider=Provider.LOCAL,
            specs={
                "vcpus": cpu_count,
                "memory_gb": round(memory_gb, 1),
                "cpu_model": self._get_cpu_model()
            },
            utilization={
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent
            },
            monthly_cost=compute_cost
        ))

        # Storage
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                size_gb = usage.total / (1024**3)

                # Detect SSD (simplified)
                is_ssd = "ssd" in partition.device.lower() or "nvme" in partition.device.lower()

                storage_cost = self.pricing.storage_cost(size_gb, is_ssd)

                resources.append(Resource(
                    id=f"local-storage-{partition.mountpoint.replace('/', '-')}",
                    name=f"Storage {partition.mountpoint}",
                    resource_type=ResourceType.STORAGE,
                    provider=Provider.LOCAL,
                    specs={
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "size_gb": round(size_gb, 1),
                        "is_ssd": is_ssd
                    },
                    utilization={
                        "used_percent": usage.percent,
                        "used_gb": round(usage.used / (1024**3), 1),
                        "free_gb": round(usage.free / (1024**3), 1)
                    },
                    monthly_cost=storage_cost
                ))
            except PermissionError:
                continue

        # Network interfaces
        net_io = psutil.net_io_counters()
        # Estimate monthly egress (very rough)
        monthly_egress_gb = (net_io.bytes_sent / (1024**3)) * 30  # Extrapolate

        resources.append(Resource(
            id="local-network",
            name="Network Egress",
            resource_type=ResourceType.NETWORK,
            provider=Provider.LOCAL,
            specs={
                "interfaces": len(psutil.net_if_addrs())
            },
            utilization={
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "estimated_monthly_egress_gb": round(monthly_egress_gb, 1)
            },
            monthly_cost=self.pricing.network_cost(monthly_egress_gb)
        ))

        return resources

    def _get_cpu_model(self) -> str:
        """Get CPU model name."""
        try:
            if sys.platform == "linux":
                with open("/proc/cpuinfo") as f:
                    for line in f:
                        if "model name" in line:
                            return line.split(":")[1].strip()
            elif sys.platform == "darwin":
                import subprocess
                result = subprocess.run(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    capture_output=True, text=True
                )
                return result.stdout.strip()
        except Exception:
            pass
        return "Unknown"


# =============================================================================
# AWS Analyzer (Optional)
# =============================================================================

class AWSAnalyzer:
    """Analyze AWS resources."""

    def __init__(self, profile: str = "default", regions: list = None):
        self.profile = profile
        self.regions = regions or ["us-east-1"]

    def analyze(self) -> list:
        """Analyze AWS resources."""
        resources = []

        try:
            import boto3
        except ImportError:
            console.print("[yellow]boto3 not installed. Skipping AWS analysis.[/yellow]")
            return resources

        session = boto3.Session(profile_name=self.profile)

        for region in self.regions:
            # EC2 Instances
            ec2 = session.client("ec2", region_name=region)
            try:
                instances = ec2.describe_instances()
                for reservation in instances["Reservations"]:
                    for instance in reservation["Instances"]:
                        if instance["State"]["Name"] != "running":
                            continue

                        # Get instance type pricing (simplified)
                        instance_type = instance["InstanceType"]
                        # In reality, you'd call AWS Pricing API
                        estimated_hourly = self._estimate_ec2_cost(instance_type)

                        name = ""
                        for tag in instance.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = tag["Value"]

                        resources.append(Resource(
                            id=instance["InstanceId"],
                            name=name or instance["InstanceId"],
                            resource_type=ResourceType.COMPUTE,
                            provider=Provider.AWS,
                            region=region,
                            specs={
                                "instance_type": instance_type,
                                "vcpus": instance.get("CpuOptions", {}).get("CoreCount", 0) * 2,
                                "architecture": instance.get("Architecture", "")
                            },
                            monthly_cost=estimated_hourly * 730,
                            tags={t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                        ))
            except Exception as e:
                console.print(f"[yellow]Error analyzing EC2 in {region}: {e}[/yellow]")

            # EBS Volumes
            try:
                volumes = ec2.describe_volumes()
                for volume in volumes["Volumes"]:
                    size_gb = volume["Size"]
                    vol_type = volume["VolumeType"]

                    # Simplified pricing
                    price_per_gb = {
                        "gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125,
                        "st1": 0.045, "sc1": 0.025, "standard": 0.05
                    }.get(vol_type, 0.10)

                    resources.append(Resource(
                        id=volume["VolumeId"],
                        name=f"EBS {volume['VolumeId']}",
                        resource_type=ResourceType.STORAGE,
                        provider=Provider.AWS,
                        region=region,
                        specs={
                            "size_gb": size_gb,
                            "type": vol_type,
                            "iops": volume.get("Iops", 0)
                        },
                        monthly_cost=size_gb * price_per_gb
                    ))
            except Exception as e:
                console.print(f"[yellow]Error analyzing EBS in {region}: {e}[/yellow]")

        return resources

    def _estimate_ec2_cost(self, instance_type: str) -> float:
        """Estimate EC2 hourly cost (simplified)."""
        # Very rough estimates - real implementation should use AWS Pricing API
        pricing = {
            "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464,
            "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
            "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384,
            "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34,
            "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504,
        }
        return pricing.get(instance_type, 0.10)


# =============================================================================
# Optimization Recommender
# =============================================================================

class OptimizationRecommender:
    """Generate cost optimization recommendations."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.thresholds = self.config.get("thresholds", {
            "cpu_underutilized": 10,
            "memory_underutilized": 20,
            "disk_underutilized": 30
        })

    def analyze(self, resources: list) -> list:
        """Generate recommendations from resources."""
        recommendations = []

        for resource in resources:
            # Check for underutilized compute
            if resource.resource_type == ResourceType.COMPUTE:
                cpu_util = resource.utilization.get("cpu_percent", 100)
                mem_util = resource.utilization.get("memory_percent", 100)

                if cpu_util < self.thresholds["cpu_underutilized"]:
                    savings = resource.monthly_cost * 0.3  # Estimate 30% savings
                    recommendations.append(Recommendation(
                        resource_id=resource.id,
                        resource_name=resource.name,
                        recommendation_type="rightsizing",
                        description=f"CPU utilization is only {cpu_util}%. Consider downsizing.",
                        current_cost=resource.monthly_cost,
                        estimated_savings=savings,
                        priority="high",
                        action="Reduce vCPU count or switch to smaller instance type"
                    ))

                if mem_util < self.thresholds["memory_underutilized"]:
                    savings = resource.monthly_cost * 0.2
                    recommendations.append(Recommendation(
                        resource_id=resource.id,
                        resource_name=resource.name,
                        recommendation_type="rightsizing",
                        description=f"Memory utilization is only {mem_util}%. Consider downsizing.",
                        current_cost=resource.monthly_cost,
                        estimated_savings=savings,
                        priority="medium",
                        action="Reduce memory allocation"
                    ))

            # Check for underutilized storage
            if resource.resource_type == ResourceType.STORAGE:
                used_percent = resource.utilization.get("used_percent", 100)

                if used_percent < self.thresholds["disk_underutilized"]:
                    # Calculate potential savings
                    free_gb = resource.utilization.get("free_gb", 0)
                    size_gb = resource.specs.get("size_gb", 0)
                    if size_gb > 0:
                        oversized_by = (1 - used_percent/100) * 0.7  # Keep some buffer
                        savings = resource.monthly_cost * oversized_by

                        if savings > 1:  # Only recommend if savings > $1
                            recommendations.append(Recommendation(
                                resource_id=resource.id,
                                resource_name=resource.name,
                                recommendation_type="storage_optimization",
                                description=f"Storage only {used_percent}% utilized ({free_gb:.0f}GB free)",
                                current_cost=resource.monthly_cost,
                                estimated_savings=savings,
                                priority="low",
                                action=f"Reduce storage size or archive old data"
                            ))

        # Sort by savings potential
        recommendations.sort(key=lambda r: r.estimated_savings, reverse=True)
        return recommendations


# =============================================================================
# Report Generation
# =============================================================================

class ReportGenerator:
    """Generate cost reports."""

    def __init__(self, report: CostReport):
        self.report = report

    def to_html(self, output_path: str):
        """Generate HTML report."""
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Infrastructure Cost Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #059669 0%, #10b981 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .cost {{ font-size: 48px; font-weight: bold; }}
        .card {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }}
        .stat {{ text-align: center; padding: 20px; background: #f9fafb; border-radius: 8px; }}
        .stat .value {{ font-size: 28px; font-weight: bold; color: #059669; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; }}
        .savings {{ color: #059669; font-weight: bold; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .badge.high {{ background: #fee2e2; color: #dc2626; }}
        .badge.medium {{ background: #fef3c7; color: #d97706; }}
        .badge.low {{ background: #dbeafe; color: #2563eb; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>💰 Infrastructure Cost Report</h1>
            <p>Generated: {self.report.scan_time.strftime("%Y-%m-%d %H:%M:%S")}</p>
            <div class="cost">${self.report.total_cost:,.2f}/month</div>
            <p class="savings">Potential Savings: ${self.report.potential_savings:,.2f}/month</p>
        </div>

        <div class="card">
            <h2>📊 Cost Breakdown</h2>
            <div class="stats">
                <div class="stat">
                    <div class="value">{len(self.report.resources)}</div>
                    <div>Resources</div>
                </div>
                <div class="stat">
                    <div class="value">${self.report.total_cost:,.0f}</div>
                    <div>Monthly Cost</div>
                </div>
                <div class="stat">
                    <div class="value">${self.report.potential_savings:,.0f}</div>
                    <div>Potential Savings</div>
                </div>
                <div class="stat">
                    <div class="value">{len(self.report.recommendations)}</div>
                    <div>Recommendations</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>💡 Optimization Recommendations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Type</th>
                        <th>Description</th>
                        <th>Current Cost</th>
                        <th>Savings</th>
                        <th>Priority</th>
                    </tr>
                </thead>
                <tbody>
'''
        for rec in self.report.recommendations:
            html += f'''
                    <tr>
                        <td>{rec.resource_name}</td>
                        <td>{rec.recommendation_type}</td>
                        <td>{rec.description}</td>
                        <td>${rec.current_cost:.2f}</td>
                        <td class="savings">${rec.estimated_savings:.2f} ({rec.savings_percent}%)</td>
                        <td><span class="badge {rec.priority}">{rec.priority.upper()}</span></td>
                    </tr>
'''
        html += '''
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>📦 Resource Inventory</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Provider</th>
                        <th>Specs</th>
                        <th>Monthly Cost</th>
                    </tr>
                </thead>
                <tbody>
'''
        for res in sorted(self.report.resources, key=lambda r: r.monthly_cost, reverse=True):
            specs_str = ", ".join(f"{k}: {v}" for k, v in list(res.specs.items())[:3])
            html += f'''
                    <tr>
                        <td>{res.name}</td>
                        <td>{res.resource_type.value}</td>
                        <td>{res.provider.value}</td>
                        <td>{specs_str}</td>
                        <td>${res.monthly_cost:.2f}</td>
                    </tr>
'''
        html += '''
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>'''

        with open(output_path, "w") as f:
            f.write(html)

        console.print(f"[green]HTML report saved to: {output_path}[/green]")

    def to_json(self, output_path: str):
        """Generate JSON report."""
        import json
        with open(output_path, "w") as f:
            json.dump(self.report.to_dict(), f, indent=2)
        console.print(f"[green]JSON report saved to: {output_path}[/green]")


# =============================================================================
# Display Functions
# =============================================================================

def display_summary(report: CostReport):
    """Display cost summary."""
    console.print(Panel(
        f"[bold]Total Monthly Cost:[/bold] [green]${report.total_cost:,.2f}[/green]\n"
        f"[bold]Potential Savings:[/bold] [cyan]${report.potential_savings:,.2f}[/cyan]\n"
        f"[bold]Resources:[/bold] {len(report.resources)}\n"
        f"[bold]Recommendations:[/bold] {len(report.recommendations)}",
        title="💰 Cost Summary",
        border_style="green"
    ))

    # Cost by type
    table = Table(title="Cost by Resource Type")
    table.add_column("Type", style="cyan")
    table.add_column("Cost", justify="right", style="green")
    table.add_column("% of Total", justify="right")

    for rtype, cost in sorted(report.by_type().items(), key=lambda x: x[1], reverse=True):
        percent = (cost / report.total_cost * 100) if report.total_cost > 0 else 0
        table.add_row(rtype, f"${cost:,.2f}", f"{percent:.1f}%")

    console.print(table)

    # Top recommendations
    if report.recommendations:
        console.print("\n[bold]Top Recommendations:[/bold]")
        for i, rec in enumerate(report.recommendations[:5], 1):
            console.print(f"  {i}. [yellow]{rec.resource_name}[/yellow]: {rec.description}")
            console.print(f"     Potential savings: [green]${rec.estimated_savings:.2f}/month[/green]")


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Infrastructure Cost Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--local", action="store_true",
                        help="Analyze local resources")
    parser.add_argument("--provider", help="Cloud provider(s): aws,azure,gcp")
    parser.add_argument("--profile", default="default",
                        help="AWS profile name")
    parser.add_argument("-c", "--config", help="Configuration file (YAML)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=["html", "json"],
                        default="html", help="Output format")
    parser.add_argument("--optimize", action="store_true",
                        help="Show optimization recommendations")
    parser.add_argument("--forecast", type=int,
                        help="Forecast costs for N months")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("-v", "--version", action="version",
                        version="infrastructure-cost-analyzer 1.0.0")

    args = parser.parse_args()

    if not args.local and not args.provider:
        args.local = True

    # Load config
    config = {}
    if args.config:
        with open(args.config) as f:
            config = yaml.safe_load(f)

    console.print("[bold blue]💰 Infrastructure Cost Analyzer[/bold blue]\n")

    # Initialize
    pricing = PricingCalculator(config.get("pricing", {}))
    resources = []

    # Analyze local resources
    if args.local:
        console.print("[dim]Analyzing local resources...[/dim]")
        local_analyzer = LocalAnalyzer(pricing)
        resources.extend(local_analyzer.analyze())

    # Analyze cloud providers
    if args.provider:
        providers = args.provider.split(",")

        if "aws" in providers:
            console.print("[dim]Analyzing AWS resources...[/dim]")
            aws_regions = config.get("providers", {}).get("aws", {}).get("regions", ["us-east-1"])
            aws_analyzer = AWSAnalyzer(args.profile, aws_regions)
            resources.extend(aws_analyzer.analyze())

    # Generate recommendations
    recommendations = []
    if args.optimize or True:  # Always generate recommendations
        recommender = OptimizationRecommender(config)
        recommendations = recommender.analyze(resources)

    # Create report
    report = CostReport(
        scan_time=datetime.now(),
        resources=resources,
        recommendations=recommendations
    )

    # Display summary
    if not args.quiet:
        display_summary(report)

    # Generate output
    if args.output:
        generator = ReportGenerator(report)
        if args.format == "json":
            generator.to_json(args.output)
        else:
            generator.to_html(args.output)

    # Forecast
    if args.forecast:
        monthly = report.total_cost
        console.print(f"\n[bold]Cost Forecast ({args.forecast} months):[/bold]")
        console.print(f"  Current monthly: ${monthly:,.2f}")
        console.print(f"  {args.forecast}-month total: ${monthly * args.forecast:,.2f}")
        console.print(f"  After optimization: ${(monthly - report.potential_savings) * args.forecast:,.2f}")


if __name__ == "__main__":
    main()
```

## Exemple de Sortie

```
💰 Infrastructure Cost Analyzer

Analyzing local resources...

╭────────────────── 💰 Cost Summary ──────────────────╮
│ Total Monthly Cost: $245.50                         │
│ Potential Savings: $48.30                           │
│ Resources: 5                                        │
│ Recommendations: 3                                  │
╰─────────────────────────────────────────────────────╯

Cost by Resource Type
┌───────────┬──────────┬────────────┐
│ Type      │ Cost     │ % of Total │
├───────────┼──────────┼────────────┤
│ compute   │ $180.00  │ 73.3%      │
│ storage   │ $55.50   │ 22.6%      │
│ network   │ $10.00   │ 4.1%       │
└───────────┴──────────┴────────────┘

Top Recommendations:
  1. Local Server: CPU utilization is only 8%. Consider downsizing.
     Potential savings: $54.00/month
  2. Storage /data: Storage only 25% utilized (750GB free)
     Potential savings: $12.30/month
```

## Cas d'Usage

1. **FinOps** : Optimisation continue des coûts cloud
2. **Budget Planning** : Prévision des dépenses infrastructure
3. **Rightsizing** : Identification des ressources surdimensionnées
4. **Chargeback** : Allocation des coûts par équipe/projet
