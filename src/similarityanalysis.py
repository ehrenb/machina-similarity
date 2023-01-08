import json

import ssdeep

from machina.core.worker import Worker

class SimilarityAnalysis(Worker):

    # Invoked explicitly
    types = []

    def __init__(self, *args, **kwargs):
        super(SimilarityAnalysis, self).__init__(*args, **kwargs)

    def callback(self, data, properties):
        # self.logger.info(data)
        data = json.loads(data)
        ssdeep_threshold = int(self.config['worker']['ssdeep_threshold'])
        comparison_rules = self.config['worker']['comparison_type_rules']

        # resolve obj
        obj_cls = self.resolve_db_node_cls(data['type'])
        obj_node_type = obj_cls.__name__.lower()
        obj = obj_cls.nodes.get(uid=data['uid'])

        # TODO: smooth this out
        types_to_compare = []
        for stype, ttypes in comparison_rules.items():
            # ['*']:['*'] everything is compared to everything, also *:['apk'] will act identically - "everything is compared to apk, and apk is compared to everything"
            if stype == '*' or '*' in ttypes:
                types_to_compare = self.config['types']['available_types'].copy()
                # types_to_compare.remove('*')
                break
            # ['apk']:['jar','dex']
            if obj_node_type == stype:
                types_to_compare = ttypes
            # ['jar']:['apk','dex']
            if obj_node_type in ttypes:
                types_to_compare = [stype]

        self.logger.info(f"Comparing against types: {types_to_compare}")

        for type_to_compare in types_to_compare:
            c = self.resolve_db_node_cls(type_to_compare)
            targets = c.nodes.all()
            for t in targets:
                # avoid comparing with self
                if t.uid == obj.uid:
                    continue
                # ensure node to compare against has ssdeep computed
                if t.ssdeep:
                    # do compare
                    result = ssdeep.compare(obj.ssdeep, t.ssdeep)
                    # check threshold
                    if result > ssdeep_threshold:
                        self.logger.info(f"Establishing similarity link between {obj.uid} {t.uid} with result {result}")

                        data = {
                            "measurements": {
                                "ssdeep_similarity": result
                            }
                        }

                        similarity_rel = obj.similar.connect(t, data).save()
                    else:
                        self.logger.info(f"ssdeep comparsion only resulted in similarity of: {result}, not enough for link")
                else:
                    self.logger.info(f"No ssdeep for {t.uid}")
