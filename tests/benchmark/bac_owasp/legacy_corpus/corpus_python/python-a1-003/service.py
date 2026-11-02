DOCUMENTS = {1: {"id": 1, "owner_id": 7, "title": "Q3 plan"}}


class DocumentService:
    def get(self, document_id):
        return DOCUMENTS.get(int(document_id))
