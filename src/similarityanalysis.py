from datetime import timedelta, datetime
import json

import ssdeep

from machina.core.periodic_worker import PeriodicWorker
from machina.core.models import Artifact
from machina.core.models.utils import resolve_db_node_cls

class SimilarityAnalysis(PeriodicWorker):
    """Compare ssdeep hashes for configured nodes periodically, create Similar bi-directional relationship where the score meets the configured threshold.  Will not create duplicate Similar relationships.
    If the threshold is changed between restarts, this module will ADD new relationships if the the new threshold applies.  It will not remove relationships. """
    
    def __init__(self, *args, **kwargs):
        super(SimilarityAnalysis, self).__init__(*args, **kwargs)

    def callback(self):
        
        ssdeep_threshold = int(self.config['worker']['ssdeep_threshold'])
        comparison_rules = self.config['worker']['comparison_type_rules']

        source_types = []
        for stype, ttypes in comparison_rules.items():

            source_types = [stype]
            source_classes = []

            target_types = ttypes
            target_classes = []

            # '*':['*'] everything is compared to everything, 
            # also '*':['apk'] will behave like - "everything is compared to apk, and apk is compared to everything"
            if stype == '*':
                source_types = self.config['types']['available_types'].copy()
            if '*' in ttypes:
                target_types = self.config['types']['available_types'].copy()

            # resolve classes
            for source_type in source_types:
                source_classes.append(resolve_db_node_cls(source_type))
            for target_type in target_types:
                target_classes.append(resolve_db_node_cls(target_type))

            for source_class in source_classes:
                source_nodes = source_class.nodes.filter(ssdeep__isnull=False)
                for target_class in target_classes:
                    target_nodes = target_class.nodes.filter(ssdeep__isnull=False)

                    for source_node in source_nodes:
                        for target_node in target_nodes:
                            # in the case *:* , dont compare two of the same exact nodes (or identical node data)
                            if source_node.uid == target_node.uid:
                                self.logger.debug(f"Skipping comparison to self uid: {source_node.uid}")
                                continue

                            result = ssdeep.compare(source_node.ssdeep, target_node.ssdeep)
                            if result > ssdeep_threshold:
                                data = {
                                    "measurements": {
                                        "ssdeep_similarity": result
                                    }
                                }

                                # see if these two node already have a relationship
                                # and if it does, see if the new ssdeep_similarity is different and update
                                similar_rel = source_node.similar.relationship(target_node)
                                if similar_rel:
                                    self.logger.debug(f"This relationship between uid:{source_node.uid} uid:{target_node.uid} already exists..checking to see if scores need updating")
                                    if similar_rel.measurements['ssdeep_similarity'] != result:
                                        self.logger.debug(f"New ssdeep score being updated: {result}")
                                        similar_rel.measurements['ssdeep_similarity'] = result
                                else:
                                    self.logger.info(f"Establishing similarity link between uid:{source_node.uid} uid:{target_node.uid} with result {result}")
                                    similarity_rel = source_node.similar.connect(target_node, data).save()
                            else:
                                self.logger.info(f"ssdeep comparison between uid:{source_node.uid} uid:{target_node.uid} only resulted in similarity of: {result}, not enough for link")

