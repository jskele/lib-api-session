package ee.iglu.skeleton.libs.session;

public interface ApiSessionSerializer {

	String writeAsToken(Object session);

	<T> T readFromToken(String token, Class<T> sessionClass);

}
