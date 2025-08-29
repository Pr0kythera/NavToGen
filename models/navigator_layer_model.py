"""
Navigator Layer Data Model
=========================

This module defines data structures for creating MITRE ATT&CK Navigator layers.
The Navigator is a web-based visualization tool that displays technique coverage
across the ATT&CK matrix, and it requires a specific JSON format.

Think of this module as the "blueprint translator" - it takes our internal analysis
results and converts them into the exact format that the Navigator tool expects.
This separation allows us to focus on the analysis logic elsewhere while keeping
the output formatting concerns isolated here.

The structures defined here strictly follow the Navigator layer format specification
version 4.5, ensuring compatibility with the official MITRE Navigator tool.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional

from config import (
    NAVIGATOR_VERSION, 
    LAYER_VERSION, 
    DEFAULT_ATTACK_VERSION,
    COVERAGE_COLORS
)


@dataclass
class TechniqueEntry:
    """
    Represents a single technique entry in a Navigator layer.
    
    Each technique in the Navigator needs specific properties to control
    how it appears and behaves in the visualization. This class encapsulates
    all those properties in a clean, manageable way.
    
    Think of this as a single "cell" in the ATT&CK matrix visualization,
    with all the information needed to display and interact with that cell.
    
    Attributes:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1055")
        score: Numeric score (0-100) used for coloring and analysis
        color: Hex color code for this technique's visualization
        comment: Tooltip text shown when hovering over the technique
        enabled: Whether this technique should be visible in the layer
        metadata: Additional key-value pairs for detailed information
        links: External links related to this technique
        show_subtechniques: Whether to expand sub-techniques in the display
    """
    
    technique_id: str
    score: int = 1
    color: str = ""
    comment: str = ""
    enabled: bool = True
    metadata: List[Dict[str, str]] = field(default_factory=list)
    links: List[Dict[str, str]] = field(default_factory=list)
    show_subtechniques: bool = False
    
    def add_metadata(self, name: str, value: str) -> None:
        """
        Add a metadata entry to this technique.
        
        Metadata appears in the Navigator's technique details and can provide
        additional context like rule counts, platforms, or coverage statistics.
        
        Args:
            name: Metadata field name (e.g., "Rule Count")
            value: Metadata field value (e.g., "5")
        """
        self.metadata.append({"name": name, "value": value})
    
    def add_link(self, label: str, url: str) -> None:
        """
        Add an external link to this technique.
        
        Links allow users to navigate to related documentation, rule repositories,
        or other relevant resources directly from the Navigator interface.
        
        Args:
            label: Display text for the link
            url: Target URL
        """
        self.links.append({"label": label, "url": url})
    
    def set_coverage_level(self, rule_count: int) -> None:
        """
        Set the color and score based on rule coverage count.
        
        This method implements our coverage visualization logic, using different
        colors to represent different levels of detection coverage.
        
        Args:
            rule_count: Number of rules covering this technique
        """
        if rule_count >= 5:
            self.score = 100
            self.color = COVERAGE_COLORS['high_coverage']
        elif rule_count >= 2:
            self.score = 60
            self.color = COVERAGE_COLORS['medium_coverage']  
        else:
            self.score = 30
            self.color = COVERAGE_COLORS['low_coverage']
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert this technique entry to Navigator-compatible dictionary format.
        
        The Navigator expects technique entries in a specific format. This method
        handles the conversion, ensuring we include all required fields and
        format them correctly.
        
        Returns:
            Dict[str, Any]: Navigator-compatible technique entry
        """
        return {
            "techniqueID": self.technique_id,
            "score": self.score,
            "color": self.color,
            "comment": self.comment,
            "enabled": self.enabled,
            "metadata": self.metadata,
            "links": self.links,
            "showSubtechniques": self.show_subtechniques
        }


@dataclass
class LegendItem:
    """
    Represents a single item in the Navigator's legend.
    
    The legend helps users understand what different colors and scores mean
    in the visualization. Each legend item associates a label with a color.
    
    Attributes:
        label: Text description shown in the legend
        color: Hex color code associated with this legend item
    """
    
    label: str
    color: str
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to Navigator-compatible dictionary format."""
        return {"label": self.label, "color": self.color}


@dataclass
class LayerFilter:
    """
    Represents filtering options for the Navigator layer.
    
    Filters control which techniques are visible based on various criteria
    like platform, data source, or other attributes. This allows users to
    focus on relevant techniques for their environment.
    
    Attributes:
        platforms: List of platforms to include (e.g., ["Windows", "Linux"])
        data_sources: List of data sources to filter by
        tactics: List of tactics to include
    """
    
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list) 
    tactics: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to Navigator-compatible dictionary format."""
        filter_dict = {}
        if self.platforms:
            filter_dict["platforms"] = self.platforms
        if self.data_sources:
            filter_dict["data_sources"] = self.data_sources
        if self.tactics:
            filter_dict["tactics"] = self.tactics
        return filter_dict


@dataclass
class NavigatorLayer:
    """
    Complete representation of a MITRE ATT&CK Navigator layer.
    
    This class encapsulates all the information needed to create a fully-functional
    Navigator layer. It handles the complex nested structure required by the
    Navigator tool while providing a clean, Pythonic interface for our code.
    
    The class follows the Builder pattern - you create a layer object and then
    add techniques, configure settings, and finally export it to the Navigator format.
    
    Attributes:
        name: Human-readable name for this layer
        description: Detailed description of what this layer represents
        domain: ATT&CK domain (typically "enterprise-attack")
        attack_version: MITRE ATT&CK version this layer is based on
        techniques: List of technique entries in this layer
        legend_items: List of legend entries explaining the visualization
        layer_filter: Filter settings for this layer
        gradient_colors: Colors used for the gradient visualization
        min_value: Minimum score value for gradient scaling
        max_value: Maximum score value for gradient scaling
        hide_disabled: Whether to hide disabled techniques
        sort_order: How techniques should be sorted (0=ascending)
    """
    
    name: str
    description: str = ""
    domain: str = "enterprise-attack"
    attack_version: str = DEFAULT_ATTACK_VERSION
    techniques: List[TechniqueEntry] = field(default_factory=list)
    legend_items: List[LegendItem] = field(default_factory=list)
    layer_filter: Optional[LayerFilter] = None
    gradient_colors: List[str] = field(default_factory=lambda: ["#ff6666ff", "#ffe766ff", "#8ec843ff"])
    min_value: int = 0
    max_value: int = 100
    hide_disabled: bool = False
    sort_order: int = 0
    
    def add_technique_entry(self, technique_entry: TechniqueEntry) -> None:
        """
        Add a technique entry to this layer.
        
        Args:
            technique_entry: TechniqueEntry object to add
        """
        self.techniques.append(technique_entry)
    
    def add_technique(self, technique_id: str, score: int = 1, 
                     color: str = "", comment: str = "") -> TechniqueEntry:
        """
        Add a technique with basic properties and return the entry for further configuration.
        
        This is a convenience method that creates a TechniqueEntry and adds it to
        the layer in one step. It returns the created entry so you can add metadata,
        links, or other advanced properties.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            score: Numeric score for this technique
            color: Hex color code (optional)
            comment: Description or tooltip text
            
        Returns:
            TechniqueEntry: The created technique entry (for further configuration)
        """
        entry = TechniqueEntry(
            technique_id=technique_id,
            score=score,
            color=color,
            comment=comment
        )
        self.add_technique_entry(entry)
        return entry
    
    def add_legend_item(self, label: str, color: str) -> None:
        """
        Add an item to the legend.
        
        Args:
            label: Text description for the legend item
            color: Hex color code associated with this item
        """
        self.legend_items.append(LegendItem(label=label, color=color))
    
    def set_default_legend(self) -> None:
        """
        Set up a standard legend for coverage analysis layers.
        
        This creates a typical legend that explains coverage levels using our
        standard color scheme. Call this method to quickly set up appropriate
        legend items for most use cases.
        """
        self.legend_items = [
            LegendItem("High Coverage (5+ rules)", COVERAGE_COLORS['high_coverage']),
            LegendItem("Medium Coverage (2-4 rules)", COVERAGE_COLORS['medium_coverage']),
            LegendItem("Low Coverage (1 rule)", COVERAGE_COLORS['low_coverage'])
        ]
    
    def set_comparison_legend(self) -> None:
        """
        Set up a legend for platform comparison layers.
        
        This creates a legend appropriate for comparing coverage between
        different SIEM platforms (Elastic vs Sentinel).
        """
        self.legend_items = [
            LegendItem("Both Platforms", COVERAGE_COLORS['both_platforms']),
            LegendItem("Elastic Only", COVERAGE_COLORS['elastic_only']),
            LegendItem("Sentinel Only", COVERAGE_COLORS['sentinel_only'])
        ]
    
    def set_default_filters(self) -> None:
        """
        Set up default platform filters for enterprise environments.
        
        This configures the layer to show techniques relevant to common
        enterprise platforms and environments.
        """
        self.layer_filter = LayerFilter(
            platforms=["Linux", "macOS", "Windows", "Azure AD", "Office 365", 
                      "SaaS", "IaaS", "Google Workspace", "PRE", "Network"]
        )
    
    def sort_techniques(self, by_score: bool = False) -> None:
        """
        Sort techniques in the layer.
        
        Args:
            by_score: If True, sort by score (descending). If False, sort by technique ID.
        """
        if by_score:
            self.techniques.sort(key=lambda t: t.score, reverse=True)
        else:
            self.techniques.sort(key=lambda t: t.technique_id)
    
    def get_technique_count(self) -> int:
        """
        Get the total number of techniques in this layer.
        
        Returns:
            int: Number of technique entries
        """
        return len(self.techniques)
    
    def get_enabled_technique_count(self) -> int:
        """
        Get the number of enabled techniques in this layer.
        
        Returns:
            int: Number of enabled technique entries
        """
        return sum(1 for t in self.techniques if t.enabled)
    
    def get_coverage_summary(self) -> Dict[str, int]:
        """
        Get a summary of coverage levels in this layer.
        
        This analyzes the scores of all techniques and categorizes them
        into coverage levels, providing a quick overview of overall coverage.
        
        Returns:
            Dict[str, int]: Summary with counts for each coverage level
        """
        high_coverage = sum(1 for t in self.techniques if t.score >= 80)
        medium_coverage = sum(1 for t in self.techniques if 40 <= t.score < 80)
        low_coverage = sum(1 for t in self.techniques if t.score < 40)
        
        return {
            "high_coverage": high_coverage,
            "medium_coverage": medium_coverage, 
            "low_coverage": low_coverage,
            "total_techniques": len(self.techniques)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert this layer to Navigator-compatible JSON format.
        
        This method performs the critical transformation from our internal
        data structures to the exact format expected by the MITRE ATT&CK Navigator.
        The resulting dictionary can be serialized to JSON and imported directly
        into the Navigator tool.
        
        Returns:
            Dict[str, Any]: Complete Navigator layer in the expected format
        """
        # Build the core layer structure
        layer_dict = {
            "name": self.name,
            "versions": {
                "attack": self.attack_version,
                "navigator": NAVIGATOR_VERSION,
                "layer": LAYER_VERSION
            },
            "domain": self.domain,
            "description": self.description,
            "sorting": self.sort_order,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": False,
                "showName": True,
                "countUnscored": False
            },
            "hideDisabled": self.hide_disabled,
            "techniques": [t.to_dict() for t in self.techniques],
            "gradient": {
                "colors": self.gradient_colors,
                "minValue": self.min_value,
                "maxValue": self.max_value
            },
            "legendItems": [item.to_dict() for item in self.legend_items],
            "metadata": [],
            "links": []
        }
        
        # Add filters if configured
        if self.layer_filter:
            filter_dict = self.layer_filter.to_dict()
            if filter_dict:  # Only add if there are actual filters
                layer_dict["filters"] = filter_dict
        
        return layer_dict
    
    def save_to_file(self, file_path: str) -> None:
        """
        Save this layer directly to a JSON file.
        
        This is a convenience method that handles the JSON serialization
        and file writing in one step.
        
        Args:
            file_path: Path where the JSON file should be saved
            
        Raises:
            IOError: If the file cannot be written
        """
        import json
        
        layer_dict = self.to_dict()
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(layer_dict, f, indent=2, ensure_ascii=False)
        except IOError as e:
            raise IOError(f"Failed to save layer to {file_path}: {str(e)}")
    
    def __str__(self) -> str:
        """Provide a clean string representation for logging and debugging."""
        return f"NavigatorLayer(name='{self.name}', techniques={len(self.techniques)}, domain={self.domain})"
    
    def __post_init__(self):
        """Perform validation and setup after object creation."""
        # Ensure we have a description if none was provided
        if not self.description:
            self.description = f"Navigator layer '{self.name}' generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Set up default filters if none provided
        if self.layer_filter is None:
            self.set_default_filters()
