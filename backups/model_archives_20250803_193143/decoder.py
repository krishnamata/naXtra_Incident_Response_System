from app.extensions import db

class Decoder(db.Model):
    __tablename__ = 'decoders'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text)  # optional: store full decoder content

    def __repr__(self):
        return f"<Decoder {self.id} - {self.title}>"
